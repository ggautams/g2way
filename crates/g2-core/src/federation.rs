//! Apollo Federation support (milestone M9, ADR-0011): the schema-side
//! machinery for the `subgraph` and `supergraph` GraphQL execution modes.
//!
//! Three jobs, all config-time (route builds and admin writes; nothing here
//! runs on the hot path):
//!
//! - **Parsing subgraph SDL**: federation SDL applies directives (`@key`,
//!   `@external`, …) it rarely defines. [`parse_subgraph_schema`] injects
//!   the missing definitions before validating, so a pasted subgraph SDL
//!   compiles as-is.
//! - **Subgraph augmentation** ([`augment_subgraph_sdl`]): `subgraph` mode
//!   polices a federating router's traffic, which selects the reserved
//!   `_service`/`_entities` root fields. The configured SDL is extended
//!   with those definitions (skipping any it already carries) so such
//!   requests validate.
//! - **Composition** ([`compose`]): `supergraph` mode merges the subgraph
//!   SDLs into the one schema clients see, and derives the ownership
//!   tables ([`ComposedSupergraph`]) the executor plans with. The merge is
//!   a deliberate v1 subset — flat scalar keys, object entities, identical
//!   value types — and every unsupported shape is a loud error, never a
//!   silent misexecution (ADR-0011 §4).

use std::collections::{BTreeMap, BTreeSet};

use apollo_compiler::ast;
use apollo_compiler::collections::IndexMap;
use apollo_compiler::schema::{Component, ExtendedType, ObjectType};
use apollo_compiler::validation::Valid;
use apollo_compiler::{Name, Schema};

/// Directives the federation spec defines; injected when a subgraph SDL
/// applies them without defining them, and stripped from composed schemas.
const FEDERATION_DIRECTIVES: &[(&str, &str)] = &[
    (
        "key",
        "directive @key(fields: _FieldSet!, resolvable: Boolean = true) \
         repeatable on OBJECT | INTERFACE",
    ),
    (
        "external",
        "directive @external on OBJECT | FIELD_DEFINITION",
    ),
    (
        "requires",
        "directive @requires(fields: _FieldSet!) on FIELD_DEFINITION",
    ),
    (
        "provides",
        "directive @provides(fields: _FieldSet!) on FIELD_DEFINITION",
    ),
    (
        "shareable",
        "directive @shareable repeatable on OBJECT | FIELD_DEFINITION",
    ),
    ("extends", "directive @extends on OBJECT | INTERFACE"),
    (
        "override",
        "directive @override(from: String!) on FIELD_DEFINITION",
    ),
    (
        "inaccessible",
        "directive @inaccessible on FIELD_DEFINITION | OBJECT | INTERFACE | UNION \
         | ARGUMENT_DEFINITION | SCALAR | ENUM | ENUM_VALUE | INPUT_OBJECT \
         | INPUT_FIELD_DEFINITION",
    ),
    (
        "tag",
        "directive @tag(name: String!) repeatable on FIELD_DEFINITION | OBJECT \
         | INTERFACE | UNION | ARGUMENT_DEFINITION | SCALAR | ENUM | ENUM_VALUE \
         | INPUT_OBJECT | INPUT_FIELD_DEFINITION",
    ),
    (
        "link",
        "directive @link(url: String!, as: String, for: link__Purpose, \
         import: [link__Import]) repeatable on SCHEMA",
    ),
];

/// Types the federation spec reserves; injected when missing, and never
/// carried into a composed schema.
const FEDERATION_TYPES: &[(&str, &str)] = &[
    ("_FieldSet", "scalar _FieldSet"),
    ("_Any", "scalar _Any"),
    ("_Service", "type _Service { sdl: String }"),
    ("link__Import", "scalar link__Import"),
    ("link__Purpose", "enum link__Purpose { SECURITY EXECUTION }"),
];

/// Reserved federation type names, skipped during composition (a subgraph
/// SDL exported from a running federation server carries them).
const RESERVED_TYPES: &[&str] = &[
    "_Any",
    "_FieldSet",
    "_Service",
    "_Entity",
    "link__Import",
    "link__Purpose",
];

/// Whether `name` is a federation directive (stripped from composed
/// schemas).
fn is_federation_directive(name: &str) -> bool {
    FEDERATION_DIRECTIVES.iter().any(|(n, _)| *n == name)
}

/// Folds an apollo diagnostic list into one `;`-joined line.
fn reasons(errors: &apollo_compiler::validation::DiagnosticList) -> String {
    errors
        .iter()
        .map(|d| d.error.to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

/// Parses an SDL without validating, so the prelude can be derived from
/// what it already defines.
fn parse_unvalidated(sdl: &str) -> Result<Schema, String> {
    Schema::parse(sdl, "subgraph.graphql")
        .map_err(|e| format!("subgraph SDL does not parse: {}", reasons(&e.errors)))
}

/// The federation definitions `parsed` is missing, as SDL text (empty when
/// it already defines everything — augmentation is idempotent).
fn prelude_for(parsed: &Schema) -> String {
    let mut out = String::new();
    for (name, text) in FEDERATION_DIRECTIVES {
        if !parsed.directive_definitions.contains_key(*name) {
            out.push_str(text);
            out.push('\n');
        }
    }
    for (name, text) in FEDERATION_TYPES {
        if !parsed.types.contains_key(*name) {
            out.push_str(text);
            out.push('\n');
        }
    }
    out
}

/// Parses and validates a subgraph SDL, injecting any federation directive
/// and type definitions it applies but does not define.
///
/// # Errors
///
/// Returns the parse/validation diagnostics as one string.
pub fn parse_subgraph_schema(sdl: &str) -> Result<Valid<Schema>, String> {
    let parsed = parse_unvalidated(sdl)?;
    let prelude = prelude_for(&parsed);
    Schema::parse_and_validate(format!("{prelude}{sdl}"), "subgraph.graphql")
        .map_err(|e| format!("subgraph SDL is not a valid schema: {}", reasons(&e.errors)))
}

/// Augments a subgraph SDL with the federation service machinery —
/// missing directive/type definitions, the `_Entity` union over the SDL's
/// `@key` types, and the reserved `_entities`/`_service` root fields — so
/// a federating router's requests validate against it (`subgraph`
/// execution mode, ADR-0011 §2). Definitions already present are kept,
/// making the augmentation idempotent. Returns the augmented SDL and its
/// compiled schema.
///
/// # Errors
///
/// Returns the diagnostics as one string when the SDL does not parse, has
/// no query root type, or does not validate after augmentation.
pub fn augment_subgraph_sdl(sdl: &str) -> Result<(String, Valid<Schema>), String> {
    let parsed = parse_unvalidated(sdl)?;
    let Some(query_root) = parsed
        .schema_definition
        .query
        .as_ref()
        .map(|c| c.name.clone())
    else {
        return Err("subgraph SDL must define a query root type".to_owned());
    };

    let entities: Vec<&Name> = parsed
        .types
        .iter()
        .filter_map(|(name, ty)| match ty {
            ExtendedType::Object(obj) if obj.directives.has("key") => Some(name),
            _ => None,
        })
        .collect();

    let mut augmented = prelude_for(&parsed);
    augmented.push_str(sdl);
    augmented.push('\n');
    if !entities.is_empty() && !parsed.types.contains_key("_Entity") {
        let members: Vec<&str> = entities.iter().map(|n| n.as_str()).collect();
        augmented.push_str(&format!("union _Entity = {}\n", members.join(" | ")));
    }
    let root_fields = parsed
        .get_object(&query_root)
        .map(|obj| &obj.fields)
        .ok_or_else(|| "subgraph SDL's query root type must be an object type".to_owned())?;
    let mut extensions = String::new();
    if !entities.is_empty() && !root_fields.contains_key("_entities") {
        extensions.push_str("  _entities(representations: [_Any!]!): [_Entity]!\n");
    }
    if !root_fields.contains_key("_service") {
        extensions.push_str("  _service: _Service!\n");
    }
    if !extensions.is_empty() {
        augmented.push_str(&format!("extend type {query_root} {{\n{extensions}}}\n"));
    }

    let schema = Schema::parse_and_validate(&augmented, "subgraph.graphql").map_err(|e| {
        format!(
            "subgraph SDL is not a valid schema after federation augmentation: {}",
            reasons(&e.errors)
        )
    })?;
    Ok((augmented, schema))
}

/// A composed supergraph: the client-facing schema plus the ownership
/// tables the executor plans entity fetches with (ADR-0011 §4).
#[derive(Debug)]
pub struct ComposedSupergraph {
    /// The composed SDL, federation directives stripped — what clients see
    /// through introspection and the playground.
    pub sdl: String,
    /// The compiled composed schema.
    pub schema: Valid<Schema>,
    /// `"Type.field"` → indices (into the subgraph list) of the subgraphs
    /// that resolve the field. Root fields have exactly one owner; entity
    /// fields list every subgraph defining them non-`@external`. Fields of
    /// non-entity types are absent — any subgraph returning the parent
    /// object resolves them.
    pub field_owners: BTreeMap<String, Vec<usize>>,
    /// Entity type name → per-subgraph canonical key (the first
    /// resolvable `@key`'s flat field list; `None` where the subgraph does
    /// not define the type or its key is `resolvable: false`).
    pub entity_keys: BTreeMap<String, Vec<Option<Vec<String>>>>,
}

/// Strips federation directives from an [`ast::DirectiveList`] in place.
fn strip_ast_directives(list: &mut ast::DirectiveList) {
    list.0.retain(|d| !is_federation_directive(&d.name));
}

/// A field definition with federation directives stripped (arguments
/// included).
fn strip_field(def: &ast::FieldDefinition) -> ast::FieldDefinition {
    let mut f = def.clone();
    strip_ast_directives(&mut f.directives);
    for arg in &mut f.arguments {
        strip_ast_directives(&mut arg.make_mut().directives);
    }
    f
}

/// A deep clone of a type definition with every federation directive
/// stripped, printable as composed SDL.
fn strip_type(ty: &ExtendedType) -> ExtendedType {
    fn strip_component_directives(list: &mut apollo_compiler::schema::DirectiveList) {
        list.0.retain(|d| !is_federation_directive(&d.name));
    }
    match ty {
        ExtendedType::Scalar(node) => {
            let mut t = (**node).clone();
            strip_component_directives(&mut t.directives);
            ExtendedType::Scalar(t.into())
        }
        ExtendedType::Object(node) => {
            let mut t = (**node).clone();
            strip_component_directives(&mut t.directives);
            for field in t.fields.values_mut() {
                *field = Component::new(strip_field(field));
            }
            ExtendedType::Object(t.into())
        }
        ExtendedType::Interface(node) => {
            let mut t = (**node).clone();
            strip_component_directives(&mut t.directives);
            for field in t.fields.values_mut() {
                *field = Component::new(strip_field(field));
            }
            ExtendedType::Interface(t.into())
        }
        ExtendedType::Union(node) => {
            let mut t = (**node).clone();
            strip_component_directives(&mut t.directives);
            ExtendedType::Union(t.into())
        }
        ExtendedType::Enum(node) => {
            let mut t = (**node).clone();
            strip_component_directives(&mut t.directives);
            for value in t.values.values_mut() {
                strip_ast_directives(&mut value.node.make_mut().directives);
            }
            ExtendedType::Enum(t.into())
        }
        ExtendedType::InputObject(node) => {
            let mut t = (**node).clone();
            strip_component_directives(&mut t.directives);
            for field in t.fields.values_mut() {
                strip_ast_directives(&mut field.node.make_mut().directives);
            }
            ExtendedType::InputObject(t.into())
        }
    }
}

/// The kind of a type definition, for mismatch errors.
fn kind_name(ty: &ExtendedType) -> &'static str {
    match ty {
        ExtendedType::Scalar(_) => "scalar",
        ExtendedType::Object(_) => "object",
        ExtendedType::Interface(_) => "interface",
        ExtendedType::Union(_) => "union",
        ExtendedType::Enum(_) => "enum",
        ExtendedType::InputObject(_) => "input object",
    }
}

/// A canonical argument/return signature for cross-subgraph agreement
/// checks (directives and descriptions excluded on purpose).
fn field_signature(def: &ast::FieldDefinition) -> String {
    let args: Vec<String> = def
        .arguments
        .iter()
        .map(|a| match &a.default_value {
            Some(v) => format!("{}: {} = {}", a.name, a.ty, v),
            None => format!("{}: {}", a.name, a.ty),
        })
        .collect();
    format!("({}): {}", args.join(", "), def.ty)
}

/// Parses one `@key(fields: "…")` field set under the v1 rules: a flat,
/// whitespace/comma-separated list of field names of `obj`.
fn parse_key_fields(
    type_name: &str,
    subgraph: &str,
    obj: &ObjectType,
    fields: &str,
) -> Result<Vec<String>, String> {
    let tokens: Vec<&str> = fields
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.is_empty() {
        return Err(format!(
            "subgraph `{subgraph}`: entity `{type_name}` has an empty @key"
        ));
    }
    for token in &tokens {
        if token.contains(['{', '}', '(', ')', ':', '.']) {
            return Err(format!(
                "subgraph `{subgraph}`: entity `{type_name}` @key `{fields}` uses a \
                 nested or argumented selection; only flat field lists are supported \
                 (ADR-0011)"
            ));
        }
        if !obj.fields.contains_key(*token) {
            return Err(format!(
                "subgraph `{subgraph}`: entity `{type_name}` @key names unknown \
                 field `{token}`"
            ));
        }
    }
    Ok(tokens.into_iter().map(str::to_owned).collect())
}

/// Composes named subgraph SDLs into one supergraph (ADR-0011 §4).
///
/// # Errors
///
/// Returns a one-line reason when any subgraph SDL is invalid, root types
/// are not `Query`/`Mutation`, a subgraph defines a `Subscription` root, a
/// root field is defined twice, type kinds clash, entity field
/// declarations disagree, a field is only ever `@external`, `@requires` or
/// `@override` is used, an interface carries `@key`, a value type differs
/// across subgraphs, a key breaks the v1 rules or cannot be provided by a
/// subgraph that returns the entity, or the composed schema fails final
/// validation.
pub fn compose(subgraphs: &[(String, String)]) -> Result<ComposedSupergraph, String> {
    if subgraphs.is_empty() {
        return Err("a supergraph needs at least one subgraph".to_owned());
    }
    let mut names = BTreeSet::new();
    for (name, _) in subgraphs {
        if !names.insert(name.as_str()) {
            return Err(format!("duplicate subgraph name `{name}`"));
        }
    }

    let mut schemas = Vec::with_capacity(subgraphs.len());
    for (name, sdl) in subgraphs {
        let schema = parse_subgraph_schema(sdl).map_err(|e| format!("subgraph `{name}`: {e}"))?;
        if let Some(q) = &schema.schema_definition.query {
            if q.name != "Query" {
                return Err(format!(
                    "subgraph `{name}`: the query root type must be named `Query` \
                     (got `{}`)",
                    q.name
                ));
            }
        } else {
            return Err(format!("subgraph `{name}`: no query root type"));
        }
        if let Some(m) = &schema.schema_definition.mutation {
            if m.name != "Mutation" {
                return Err(format!(
                    "subgraph `{name}`: the mutation root type must be named \
                     `Mutation` (got `{}`)",
                    m.name
                ));
            }
        }
        if schema.schema_definition.subscription.is_some() {
            return Err(format!(
                "subgraph `{name}` defines a Subscription root type; federated \
                 subscriptions are not supported (ADR-0011)"
            ));
        }
        schemas.push(schema);
    }
    let names: Vec<&str> = subgraphs.iter().map(|(n, _)| n.as_str()).collect();
    let subgraph_name = |i: usize| names[i];

    let mut field_owners: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut entity_keys: BTreeMap<String, Vec<Option<Vec<String>>>> = BTreeMap::new();

    // Root fields: single-owner, duplicates are errors (no @shareable root
    // fields in v1).
    let mut root_fields: [IndexMap<Name, (usize, ast::FieldDefinition)>; 2] =
        [IndexMap::default(), IndexMap::default()];
    for (i, schema) in schemas.iter().enumerate() {
        for (slot, root) in ["Query", "Mutation"].iter().enumerate() {
            let Some(obj) = schema.get_object(root) else {
                continue;
            };
            for (fname, fdef) in &obj.fields {
                if matches!(fname.as_str(), "_entities" | "_service") {
                    continue;
                }
                if let Some((other, _)) = root_fields[slot].get(fname) {
                    return Err(format!(
                        "root field `{root}.{fname}` is defined by both subgraph \
                         `{}` and subgraph `{}`; shared root fields are not \
                         supported (ADR-0011)",
                        subgraph_name(*other),
                        subgraph_name(i)
                    ));
                }
                root_fields[slot].insert(fname.clone(), (i, strip_field(fdef)));
                field_owners.insert(format!("{root}.{fname}"), vec![i]);
            }
        }
    }
    if root_fields[0].is_empty() {
        return Err("no subgraph defines any Query root field".to_owned());
    }

    // Group every non-root, non-reserved type by name.
    let mut groups: IndexMap<&Name, Vec<(usize, &ExtendedType)>> = IndexMap::default();
    for (i, schema) in schemas.iter().enumerate() {
        for (tname, ty) in &schema.types {
            let skip = ty.is_built_in()
                || tname.starts_with("__")
                || RESERVED_TYPES.contains(&tname.as_str())
                || matches!(tname.as_str(), "Query" | "Mutation");
            if !skip {
                groups.entry(tname).or_default().push((i, ty));
            }
        }
    }

    // Compose each type, printing SDL as we go.
    let mut out = String::new();
    for (root, slot) in [("Query", 0), ("Mutation", 1)] {
        if root_fields[slot].is_empty() {
            continue;
        }
        out.push_str(&format!("type {root} {{\n"));
        for (_, def) in root_fields[slot].values() {
            out.push_str(&format!("  {def}\n"));
        }
        out.push_str("}\n");
    }

    for (tname, defs) in &groups {
        let kind = kind_name(defs[0].1);
        for (i, ty) in defs {
            if kind_name(ty) != kind {
                return Err(format!(
                    "type `{tname}` is a {kind} in subgraph `{}` but a {} in \
                     subgraph `{}`",
                    subgraph_name(defs[0].0),
                    kind_name(ty),
                    subgraph_name(*i)
                ));
            }
            if let ExtendedType::Interface(iface) = ty {
                if iface.directives.has("key") {
                    return Err(format!(
                        "subgraph `{}`: interface `{tname}` has @key; interface \
                         entities are not supported (ADR-0011)",
                        subgraph_name(*i)
                    ));
                }
            }
        }

        let objects: Vec<(usize, &ObjectType)> = defs
            .iter()
            .filter_map(|(i, ty)| match ty {
                ExtendedType::Object(obj) => Some((*i, &**obj)),
                _ => None,
            })
            .collect();
        let is_entity = objects.iter().any(|(_, obj)| obj.directives.has("key"));

        if is_entity {
            compose_entity(
                tname,
                &objects,
                subgraphs.len(),
                &names,
                &mut field_owners,
                &mut entity_keys,
                &mut out,
            )?;
        } else {
            // Value type: definitions must be structurally identical
            // (federation directives ignored in the comparison).
            let printed = strip_type(defs[0].1).to_string();
            for (i, ty) in &defs[1..] {
                if strip_type(ty).to_string() != printed {
                    return Err(format!(
                        "type `{tname}` differs between subgraph `{}` and subgraph \
                         `{}`; non-entity types must be identical everywhere \
                         (ADR-0011)",
                        subgraph_name(defs[0].0),
                        subgraph_name(*i)
                    ));
                }
            }
            out.push_str(&printed);
            out.push('\n');
        }
    }

    // The final gate: the merge above must produce a valid schema.
    let schema = Schema::parse_and_validate(&out, "supergraph.graphql").map_err(|e| {
        format!(
            "composed supergraph schema is invalid: {}",
            reasons(&e.errors)
        )
    })?;

    Ok(ComposedSupergraph {
        sdl: out,
        schema,
        field_owners,
        entity_keys,
    })
}

/// Composes one entity type: merges fields with ownership, derives each
/// subgraph's canonical key, checks key availability, and prints the
/// composed definition.
#[allow(clippy::too_many_arguments)] // internal composition plumbing, one caller
fn compose_entity(
    tname: &Name,
    objects: &[(usize, &ObjectType)],
    subgraph_count: usize,
    names: &[&str],
    field_owners: &mut BTreeMap<String, Vec<usize>>,
    entity_keys: &mut BTreeMap<String, Vec<Option<Vec<String>>>>,
    out: &mut String,
) -> Result<(), String> {
    let subgraph_name = |i: usize| names[i];
    struct MergedField {
        signature: String,
        first_subgraph: usize,
        resolved: Option<ast::FieldDefinition>,
        owners: Vec<usize>,
    }
    let mut fields: IndexMap<&Name, MergedField> = IndexMap::default();
    let mut implements: BTreeSet<&Name> = BTreeSet::new();
    let mut keys: Vec<Option<Vec<String>>> = vec![None; subgraph_count];

    for (i, obj) in objects {
        for name in &obj.implements_interfaces {
            implements.insert(&name.name);
        }
        if let Some(key) = obj.directives.get("key") {
            let resolvable = key
                .specified_argument_by_name("resolvable")
                .and_then(|v| v.to_bool())
                .unwrap_or(true);
            if resolvable {
                let Some(spec) = key
                    .specified_argument_by_name("fields")
                    .and_then(|v| v.as_str())
                else {
                    return Err(format!(
                        "subgraph `{}`: entity `{tname}` @key `fields` must be a \
                         string",
                        subgraph_name(*i)
                    ));
                };
                keys[*i] = Some(parse_key_fields(tname, subgraph_name(*i), obj, spec)?);
            }
        }
        let type_external = obj.directives.has("external");
        for (fname, fdef) in &obj.fields {
            for (directive, why) in [
                ("requires", "@requires is not supported (ADR-0011)"),
                ("override", "@override is not supported (ADR-0011)"),
            ] {
                if fdef.directives.has(directive) {
                    return Err(format!(
                        "subgraph `{}`: `{tname}.{fname}` — {why}",
                        subgraph_name(*i)
                    ));
                }
            }
            let external = type_external || fdef.directives.has("external");
            let signature = field_signature(fdef);
            let merged = fields.entry(fname).or_insert_with(|| MergedField {
                signature: signature.clone(),
                first_subgraph: *i,
                resolved: None,
                owners: Vec::new(),
            });
            if merged.signature != signature {
                return Err(format!(
                    "entity field `{tname}.{fname}` is declared `{}` in subgraph \
                     `{}` but `{signature}` in subgraph `{}`",
                    merged.signature,
                    subgraph_name(merged.first_subgraph),
                    subgraph_name(*i)
                ));
            }
            if !external {
                merged.owners.push(*i);
                if merged.resolved.is_none() {
                    merged.resolved = Some(strip_field(fdef));
                }
            }
        }
    }

    let mut owner_union: BTreeSet<usize> = BTreeSet::new();
    for (fname, merged) in &fields {
        if merged.resolved.is_none() {
            return Err(format!(
                "entity field `{tname}.{fname}` is only ever declared @external; \
                 some subgraph must resolve it"
            ));
        }
        owner_union.extend(merged.owners.iter().copied());
        field_owners.insert(format!("{tname}.{fname}"), merged.owners.clone());
    }

    // Every subgraph that can return the entity must be able to provide the
    // key fields of every subgraph it may need to resolve fields from.
    for (p, pobj) in objects {
        for &s in &owner_union {
            if s == *p {
                continue;
            }
            match &keys[s] {
                Some(key) => {
                    if let Some(missing) =
                        key.iter().find(|f| !pobj.fields.contains_key(f.as_str()))
                    {
                        return Err(format!(
                            "subgraph `{}` returns entity `{tname}` but does not \
                             declare key field `{missing}` needed to resolve it \
                             from subgraph `{}`",
                            subgraph_name(*p),
                            subgraph_name(s)
                        ));
                    }
                }
                None => {
                    return Err(format!(
                        "subgraph `{}` resolves fields of entity `{tname}` but \
                         declares no resolvable @key",
                        subgraph_name(s)
                    ));
                }
            }
        }
    }
    entity_keys.insert(tname.to_string(), keys);

    // Print the composed definition: non-federation type directives from
    // the first definition, the union of implemented interfaces, and each
    // field from its first resolving subgraph.
    let mut header = format!("type {tname}");
    if !implements.is_empty() {
        let list: Vec<&str> = implements.iter().map(|n| n.as_str()).collect();
        header.push_str(&format!(" implements {}", list.join(" & ")));
    }
    let mut type_directives = objects[0].1.directives.clone();
    type_directives
        .0
        .retain(|d| !is_federation_directive(&d.name));
    if !type_directives.is_empty() {
        header.push_str(&type_directives.to_string());
    }
    out.push_str(&header);
    out.push_str(" {\n");
    for (_, merged) in &fields {
        let def = merged.resolved.as_ref().expect("checked above");
        out.push_str(&format!("  {def}\n"));
    }
    out.push_str("}\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS_SDL: &str = r#"
        type Query { user(id: ID!): User users: [User!]! }
        type User @key(fields: "id") { id: ID! name: String email: String }
    "#;

    const REVIEWS_SDL: &str = r#"
        type Query { topReviews: [Review!]! }
        type Review { id: ID! body: String author: User }
        type User @key(fields: "id") {
            id: ID! @external
            reviews: [Review!]
        }
    "#;

    fn pair(name: &str, sdl: &str) -> (String, String) {
        (name.to_owned(), sdl.to_owned())
    }

    fn users_reviews() -> Vec<(String, String)> {
        vec![pair("users", USERS_SDL), pair("reviews", REVIEWS_SDL)]
    }

    #[test]
    fn subgraph_sdl_parses_with_injected_federation_definitions() {
        parse_subgraph_schema(USERS_SDL).expect("valid with prelude");

        // An SDL defining its own @key keeps its definition (no duplicate).
        let own = format!(
            "directive @key(fields: String!) repeatable on OBJECT\n{}",
            "type Query { u: U } type U @key(fields: \"id\") { id: ID! }"
        );
        parse_subgraph_schema(&own).expect("own definitions kept");

        let err = parse_subgraph_schema("type Query {").unwrap_err();
        assert!(err.contains("does not parse"), "got: {err}");
    }

    #[test]
    fn augmentation_adds_service_machinery_and_is_idempotent() {
        let (sdl, schema) = augment_subgraph_sdl(USERS_SDL).expect("augments");
        let query = schema.get_object("Query").expect("query root");
        assert!(query.fields.contains_key("_service"));
        assert!(query.fields.contains_key("_entities"));
        assert!(schema.types.contains_key("_Entity"));

        // Re-augmenting the augmented SDL adds nothing new.
        let (again, _) = augment_subgraph_sdl(&sdl).expect("idempotent");
        assert_eq!(
            again.matches("_service: _Service!").count(),
            sdl.matches("_service: _Service!").count()
        );

        // No entities: `_service` only, no `_Entity` union.
        let (_, schema) = augment_subgraph_sdl("type Query { hello: String }").expect("augments");
        let query = schema.get_object("Query").expect("query root");
        assert!(query.fields.contains_key("_service"));
        assert!(!query.fields.contains_key("_entities"));
        assert!(!schema.types.contains_key("_Entity"));
    }

    #[test]
    fn augmentation_requires_a_query_root() {
        let err = augment_subgraph_sdl("type User { id: ID! }").unwrap_err();
        assert!(err.contains("query root"), "got: {err}");
    }

    #[test]
    fn composes_two_subgraphs_with_ownership_tables() {
        let composed = compose(&users_reviews()).expect("composes");

        // Root fields carry their single owner.
        assert_eq!(composed.field_owners["Query.user"], vec![0]);
        assert_eq!(composed.field_owners["Query.topReviews"], vec![1]);

        // Entity fields: `name` only in users, `reviews` only in reviews;
        // `id` is non-external only in users.
        assert_eq!(composed.field_owners["User.name"], vec![0]);
        assert_eq!(composed.field_owners["User.reviews"], vec![1]);
        assert_eq!(composed.field_owners["User.id"], vec![0]);
        assert!(
            !composed.field_owners.contains_key("Review.body"),
            "value-type fields have no owners entry"
        );

        // Keys per subgraph.
        assert_eq!(
            composed.entity_keys["User"],
            vec![Some(vec!["id".to_owned()]), Some(vec!["id".to_owned()])]
        );

        // The composed schema merges the entity and strips federation
        // directives.
        let user = composed.schema.get_object("User").expect("merged");
        for field in ["id", "name", "email", "reviews"] {
            assert!(user.fields.contains_key(field), "missing {field}");
        }
        assert!(!user.directives.has("key"));
        assert!(!composed.sdl.contains("@key"), "sdl: {}", composed.sdl);
        assert!(!composed.sdl.contains("@external"));
    }

    #[test]
    fn composition_rejects_the_unsupported_shapes() {
        type Case = (&'static str, Vec<(String, String)>, &'static str);
        let cases: Vec<Case> = vec![
            ("empty", vec![], "at least one subgraph"),
            (
                "duplicate name",
                vec![
                    pair("a", "type Query { x: Int }"),
                    pair("a", "type Query { y: Int }"),
                ],
                "duplicate subgraph name",
            ),
            (
                "duplicate root field",
                vec![
                    pair("a", "type Query { x: Int }"),
                    pair("b", "type Query { x: Int }"),
                ],
                "defined by both",
            ),
            (
                "kind clash",
                vec![
                    pair("a", "type Query { x: T } type T { id: ID }"),
                    pair("b", "type Query { y: T } enum T { A }"),
                ],
                "but a enum",
            ),
            (
                "value type mismatch",
                vec![
                    pair("a", "type Query { x: T } type T { id: ID }"),
                    pair("b", "type Query { y: T } type T { id: ID name: String }"),
                ],
                "must be identical",
            ),
            (
                "requires",
                vec![pair(
                    "a",
                    "type Query { u: U } type U @key(fields: \"id\") \
                     { id: ID! w: Int @requires(fields: \"id\") }",
                )],
                "@requires is not supported",
            ),
            (
                "override",
                vec![pair(
                    "a",
                    "type Query { u: U } type U @key(fields: \"id\") \
                     { id: ID! w: Int @override(from: \"b\") }",
                )],
                "@override is not supported",
            ),
            (
                "interface entity",
                vec![pair(
                    "a",
                    "type Query { n: N } interface N @key(fields: \"id\") { id: ID! } \
                     type X implements N { id: ID! }",
                )],
                "interface entities are not supported",
            ),
            (
                "nested key",
                vec![pair(
                    "a",
                    "type Query { u: U } type U @key(fields: \"org { id }\") \
                     { id: ID! org: O } type O { id: ID! }",
                )],
                "flat field lists",
            ),
            (
                "unknown key field",
                vec![pair(
                    "a",
                    "type Query { u: U } type U @key(fields: \"nope\") { id: ID! }",
                )],
                "unknown field `nope`",
            ),
            (
                "external only",
                vec![
                    pair(
                        "a",
                        "type Query { u: U } type U @key(fields: \"id\") \
                         { id: ID! ghost: Int @external }",
                    ),
                    pair(
                        "b",
                        "type Query { x: Int } type U @key(fields: \"id\") \
                         { id: ID! @external ghost: Int @external }",
                    ),
                ],
                "only ever declared @external",
            ),
            (
                "missing key field on a returning subgraph",
                vec![
                    pair(
                        "a",
                        "type Query { u: U } type U @key(fields: \"id\") \
                         { id: ID! name: String }",
                    ),
                    pair(
                        "b",
                        "type Query { x: Int } type U @key(fields: \"sku\") \
                         { sku: ID! stock: Int }",
                    ),
                ],
                "does not declare key field `sku`",
            ),
            (
                "field signature mismatch",
                vec![
                    pair(
                        "a",
                        "type Query { u: U } type U @key(fields: \"id\") \
                         { id: ID! n: Int }",
                    ),
                    pair(
                        "b",
                        "type Query { x: Int } type U @key(fields: \"id\") \
                         { id: ID! @external n: String }",
                    ),
                ],
                "is declared",
            ),
            (
                "wrong root name",
                vec![pair("a", "schema { query: Root } type Root { x: Int }")],
                "must be named `Query`",
            ),
            (
                "subscription root",
                vec![pair(
                    "a",
                    "type Query { x: Int } type Subscription { t: Int }",
                )],
                "federated subscriptions",
            ),
        ];
        for (label, subgraphs, needle) in cases {
            let err = compose(&subgraphs).expect_err(label);
            assert!(
                err.contains(needle),
                "{label}: expected `{needle}` in: {err}"
            );
        }
    }

    #[test]
    fn composition_ignores_provides_and_resolvable_false_keys() {
        // @provides is stripped and ignored; a resolvable: false key means
        // the subgraph is never an _entities target.
        let a = pair(
            "a",
            r#"type Query { r: R }
               type R { u: U @provides(fields: "name") }
               type U @key(fields: "id", resolvable: false) {
                   id: ID! @external
                   name: String @external
               }"#,
        );
        // `a` only references U; `b` owns it.
        let b = pair(
            "b",
            r#"type Query { u(id: ID!): U }
               type U @key(fields: "id") { id: ID! name: String }"#,
        );
        let composed = compose(&[a, b]).expect("composes");
        assert_eq!(
            composed.entity_keys["U"],
            vec![None, Some(vec!["id".to_owned()])]
        );
        assert_eq!(composed.field_owners["U.name"], vec![1]);
        assert!(!composed.sdl.contains("@provides"));
    }

    #[test]
    fn composed_value_types_and_enums_lose_tags() {
        let composed = compose(&[pair(
            "a",
            r#"type Query { s: Status w: W }
               enum Status { OK @tag(name: "x") DOWN }
               type W @tag(name: "y") { n: Int }"#,
        )])
        .expect("composes");
        assert!(!composed.sdl.contains("@tag"), "sdl: {}", composed.sdl);
        assert!(composed.schema.types.contains_key("Status"));
    }

    #[test]
    fn entity_merge_unions_interfaces_and_keeps_descriptions() {
        let a = pair(
            "a",
            r#"type Query { u: U }
               interface Named { name: String }
               "A user."
               type U implements Named @key(fields: "id") {
                   id: ID!
                   "The display name."
                   name: String
               }"#,
        );
        let b = pair(
            "b",
            r#"type Query { x: Int }
               interface Aged { age: Int }
               interface Named { name: String }
               type U implements Aged & Named @key(fields: "id") {
                   id: ID! @external
                   name: String @external
                   age: Int
               }"#,
        );
        let composed = compose(&[a, b]).expect("composes");
        let user = composed.schema.get_object("U").expect("merged");
        assert_eq!(user.implements_interfaces.len(), 2);
        assert!(composed.sdl.contains("The display name."));
    }
}
