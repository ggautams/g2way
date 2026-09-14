//! draft-cavage HTTP-Signature parsing and HMAC verification.
//!
//! Pure, synchronous helpers behind the [`auth`](crate::auth) layer's `hmac`
//! mode: parse an `Authorization: Signature …` header into
//! [`SignatureParams`], rebuild the signing string the client signed
//! ([`build_signing_string`]), and verify the signature against a shared
//! secret ([`verify`], constant-time). Policy — which algorithms an API
//! accepts, clock-skew bounds, key lookup — stays in the auth layer.

use base64::Engine as _;
use g2_core::HmacAlgorithm;
use sha2::{Sha256, Sha384, Sha512};

/// The parameters of one parsed `Authorization: Signature …` header.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SignatureParams {
    /// The `keyId` parameter, verbatim.
    pub(crate) key_id: String,
    /// The `algorithm` parameter, verbatim (matched case-insensitively
    /// against [`HmacAlgorithm::as_str`] by the auth layer).
    pub(crate) algorithm: String,
    /// The signed-header names from the `headers` parameter, lowercased;
    /// `["date"]` when the parameter is absent (draft-cavage default).
    pub(crate) headers: Vec<String>,
    /// The decoded `signature` parameter.
    pub(crate) signature: Vec<u8>,
}

/// Parses a draft-cavage `Signature` authorization header value.
///
/// Grammar: a case-insensitive `Signature ` scheme followed by
/// comma-separated `name="value"` pairs (optional whitespace around commas).
/// `keyId`, `algorithm`, and `signature` are required; `headers` is optional
/// (absent = `date`); parameter names are matched case-sensitively (the
/// draft's canonical spellings); unknown parameters are ignored (forward
/// compatibility) and duplicates are malformed (fail closed on ambiguity).
///
/// The `signature` value is percent-decoded first when it contains `%`
/// (some clients percent-encode it), then base64-decoded.
///
/// Returns `None` for anything not parseable — the auth layer maps that to
/// a `401` (no credential present), like basic auth's unparseable cases.
pub(crate) fn parse_signature_header(value: &str) -> Option<SignatureParams> {
    let rest = match value.trim().split_at_checked(10) {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("signature ") => rest,
        _ => return None,
    };

    let mut key_id: Option<String> = None;
    let mut algorithm: Option<String> = None;
    let mut headers: Option<String> = None;
    let mut signature: Option<String> = None;

    let mut rest = rest.trim_start();
    while !rest.is_empty() {
        let eq = rest.find('=')?;
        let name = rest[..eq].trim();
        let after = rest[eq + 1..].strip_prefix('"')?;
        let end = after.find('"')?;
        let value = &after[..end];
        rest = after[end + 1..].trim_start();
        match rest.strip_prefix(',') {
            Some(r) => rest = r.trim_start(),
            None if rest.is_empty() => {}
            None => return None,
        }
        let slot = match name {
            "keyId" => &mut key_id,
            "algorithm" => &mut algorithm,
            "headers" => &mut headers,
            "signature" => &mut signature,
            _ => continue, // unknown parameters: ignored
        };
        if slot.replace(value.to_owned()).is_some() {
            return None; // duplicate parameter: ambiguous, fail closed
        }
    }

    let key_id = key_id.filter(|k| !k.is_empty())?;
    let algorithm = algorithm.filter(|a| !a.is_empty())?;
    let headers = match headers {
        None => vec!["date".to_owned()],
        Some(list) => {
            let names: Vec<String> = list
                .split_whitespace()
                .map(str::to_ascii_lowercase)
                .collect();
            if names.is_empty() {
                return None; // present-but-empty `headers=""` is malformed
            }
            names
        }
    };
    let signature = signature?;
    let signature = if signature.contains('%') {
        percent_decode(&signature)?
    } else {
        signature
    };
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature)
        .ok()?;

    Some(SignatureParams {
        key_id,
        algorithm,
        headers,
        signature,
    })
}

/// Undoes percent-encoding (`%2B` → `+`, …); `+` is left alone (it is a
/// base64 character here, not a query-string space).
fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Rebuilds the string the client signed: one line per (lowercased) name in
/// `names`, joined with `\n`, no trailing newline.
///
/// - `(request-target)` → `{lowercased method} {path?query}`, byte-exact as
///   received (no percent-decoding or normalization — the client signs the
///   bytes it sends).
/// - any other name → `name: value`; multiple values of the header are
///   joined with `", "` (draft §2.3), each trimmed of surrounding
///   whitespace.
///
/// Returns `None` when a named header is absent from the request (or its
/// value is not valid UTF-8) — the signature cannot cover it.
pub(crate) fn build_signing_string(
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
    names: &[String],
) -> Option<String> {
    let mut lines = Vec::with_capacity(names.len());
    for name in names {
        if name == "(request-target)" {
            let target = uri.path_and_query().map_or(uri.path(), |pq| pq.as_str());
            lines.push(format!("{} {target}", method.as_str().to_ascii_lowercase()));
        } else {
            let mut values = Vec::new();
            for value in headers.get_all(name.as_str()) {
                values.push(value.to_str().ok()?.trim());
            }
            if values.is_empty() {
                return None;
            }
            lines.push(format!("{name}: {}", values.join(", ")));
        }
    }
    Some(lines.join("\n"))
}

/// Whether `signature` is `message`'s HMAC under `secret` and `algorithm`.
///
/// Constant-time: `hmac`'s `verify_slice` compares via `subtle` internally,
/// so a mismatch leaks nothing about how much of the tag matched.
pub(crate) fn verify(
    algorithm: HmacAlgorithm,
    secret: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    match algorithm {
        HmacAlgorithm::HmacSha256 => verify_mac::<::hmac::Hmac<Sha256>>(secret, message, signature),
        HmacAlgorithm::HmacSha384 => verify_mac::<::hmac::Hmac<Sha384>>(secret, message, signature),
        HmacAlgorithm::HmacSha512 => verify_mac::<::hmac::Hmac<Sha512>>(secret, message, signature),
    }
}

fn verify_mac<M: ::hmac::Mac + ::hmac::digest::KeyInit>(
    secret: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    // HMAC accepts keys of any length, so this cannot fail; returning
    // `false` (instead of unwrapping) keeps the hot path panic-free anyway.
    let Ok(mut mac) = <M as ::hmac::Mac>::new_from_slice(secret) else {
        return false;
    };
    mac.update(message);
    mac.verify_slice(signature).is_ok()
}

#[cfg(test)]
mod tests {
    use http::header::HeaderValue;
    use http::{HeaderMap, Method, Uri};

    use super::*;

    fn parse(value: &str) -> Option<SignatureParams> {
        parse_signature_header(value)
    }

    const FULL: &str = "Signature keyId=\"mykey\",algorithm=\"hmac-sha256\",\
                        headers=\"(request-target) date\",signature=\"aGVsbG8=\"";

    #[test]
    fn full_header_parses() {
        let params = parse(FULL).expect("parses");
        assert_eq!(params.key_id, "mykey");
        assert_eq!(params.algorithm, "hmac-sha256");
        assert_eq!(params.headers, ["(request-target)", "date"]);
        assert_eq!(params.signature, b"hello");
    }

    #[test]
    fn scheme_is_case_insensitive_and_whitespace_tolerated() {
        let params = parse(
            "  signature   keyId=\"k\" , algorithm=\"hmac-sha512\" , signature=\"aGVsbG8=\"  ",
        )
        .expect("parses");
        assert_eq!(params.key_id, "k");
        assert_eq!(params.headers, ["date"], "absent headers param defaults");
    }

    #[test]
    fn headers_param_is_lowercased_and_split() {
        let params = parse(
            "Signature keyId=\"k\",algorithm=\"a\",headers=\"(Request-Target)  X-Custom date\",\
             signature=\"aGVsbG8=\"",
        )
        .expect("parses");
        assert_eq!(params.headers, ["(request-target)", "x-custom", "date"]);
    }

    #[test]
    fn missing_required_params_are_malformed() {
        for value in [
            "Signature algorithm=\"a\",signature=\"aGVsbG8=\"", // no keyId
            "Signature keyId=\"k\",signature=\"aGVsbG8=\"",     // no algorithm
            "Signature keyId=\"k\",algorithm=\"a\"",            // no signature
            "Signature keyId=\"\",algorithm=\"a\",signature=\"aGVsbG8=\"", // empty keyId
        ] {
            assert!(parse(value).is_none(), "{value}");
        }
    }

    #[test]
    fn wrong_scheme_and_grammar_violations_are_malformed() {
        for value in [
            "Bearer abc",
            "Signature",
            "Signature keyId=k,algorithm=\"a\",signature=\"aGVsbG8=\"", // unquoted
            "Signature keyId=\"k\" algorithm=\"a\",signature=\"aGVsbG8=\"", // missing comma
            "Signature keyId=\"k\",algorithm=\"a\",signature=\"not base64!\"",
            "Signature keyId=\"k\",algorithm=\"a\",headers=\"\",signature=\"aGVsbG8=\"",
        ] {
            assert!(parse(value).is_none(), "{value}");
        }
    }

    #[test]
    fn duplicate_param_is_malformed_but_unknown_param_is_ignored() {
        assert!(
            parse("Signature keyId=\"k\",keyId=\"k2\",algorithm=\"a\",signature=\"aGVsbG8=\"")
                .is_none()
        );
        let params =
            parse("Signature keyId=\"k\",created=\"123\",algorithm=\"a\",signature=\"aGVsbG8=\"")
                .expect("unknown param ignored");
        assert_eq!(params.key_id, "k");
    }

    #[test]
    fn percent_encoded_signature_is_decoded() {
        // base64 "+9k=" percent-encoded the way some clients do.
        let params =
            parse("Signature keyId=\"k\",algorithm=\"a\",signature=\"%2B9k%3D\"").expect("parses");
        assert_eq!(params.signature, vec![0xfb, 0xd9]);
        assert!(
            parse("Signature keyId=\"k\",algorithm=\"a\",signature=\"%zz\"").is_none(),
            "bad percent escape is malformed"
        );
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn signing_string_covers_request_target_and_headers() {
        let uri: Uri = "/api/widgets?page=2".parse().expect("uri");
        let mut headers = HeaderMap::new();
        headers.insert(
            "date",
            HeaderValue::from_static("Mon, 01 Sep 2025 12:00:00 GMT"),
        );
        headers.insert("x-custom", HeaderValue::from_static("  padded  "));
        let s = build_signing_string(
            &Method::POST,
            &uri,
            &headers,
            &names(&["(request-target)", "date", "x-custom"]),
        )
        .expect("builds");
        assert_eq!(
            s,
            "post /api/widgets?page=2\ndate: Mon, 01 Sep 2025 12:00:00 GMT\nx-custom: padded"
        );
    }

    #[test]
    fn signing_string_joins_repeated_headers() {
        let uri: Uri = "/".parse().expect("uri");
        let mut headers = HeaderMap::new();
        headers.append("x-multi", HeaderValue::from_static("a"));
        headers.append("x-multi", HeaderValue::from_static("b"));
        let s = build_signing_string(&Method::GET, &uri, &headers, &names(&["x-multi"]))
            .expect("builds");
        assert_eq!(s, "x-multi: a, b");
    }

    #[test]
    fn signing_string_missing_header_is_none() {
        let uri: Uri = "/".parse().expect("uri");
        assert!(
            build_signing_string(&Method::GET, &uri, &HeaderMap::new(), &names(&["date"]))
                .is_none()
        );
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16).expect("hex")
            })
            .collect()
    }

    #[test]
    fn verify_matches_rfc_4231_known_answers() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for
        // nothing?" — pinned expected tags keep this independent of the
        // hmac crate's own correctness.
        let key = b"Jefe";
        let msg = b"what do ya want for nothing?";
        let sha256 = hex_bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        let sha384 = hex_bytes(
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
             8e2240ca5e69e2c78b3239ecfab21649",
        );
        let sha512 = hex_bytes(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        );
        assert!(verify(HmacAlgorithm::HmacSha256, key, msg, &sha256));
        assert!(verify(HmacAlgorithm::HmacSha384, key, msg, &sha384));
        assert!(verify(HmacAlgorithm::HmacSha512, key, msg, &sha512));
        assert!(!verify(HmacAlgorithm::HmacSha256, key, msg, &sha384));
        assert!(!verify(HmacAlgorithm::HmacSha256, b"jefe", msg, &sha256));
        assert!(!verify(
            HmacAlgorithm::HmacSha256,
            key,
            b"tampered",
            &sha256
        ));
    }
}
