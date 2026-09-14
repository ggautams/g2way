//! The JSON wire format crossing the host/guest boundary (ABI version 1).

use bytes::Bytes;
use g2_middleware::{HookInvocation, HookOutcome};
use http::header::{HeaderName, HeaderValue};
use http::{Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::ABI_VERSION;

/// The input document written into guest memory.
#[derive(Serialize)]
struct WireInput<'a> {
    abi_version: i32,
    hook: &'a str,
    api_id: &'a str,
    org_id: &'a str,
    plugin_config: &'a RawValue,
    request: WireRequest<'a>,
    session: Option<WireSession<'a>>,
}

/// The request view inside [`WireInput`].
#[derive(Serialize)]
struct WireRequest<'a> {
    method: &'a str,
    path: &'a str,
    query: Option<&'a str>,
    /// Repeated pairs carry multi-valued headers; values are lossy UTF-8.
    headers: Vec<(&'a str, String)>,
    client_addr: Option<String>,
}

/// The session view inside [`WireInput`].
#[derive(Serialize)]
struct WireSession<'a> {
    alias: &'a str,
}

/// The output document read back from guest memory.
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum WireOutput {
    Continue {
        #[serde(default)]
        set_headers: Vec<(String, String)>,
        #[serde(default)]
        remove_headers: Vec<String>,
    },
    Respond {
        response: WireResponse,
    },
}

/// The short-circuit response inside [`WireOutput::Respond`].
#[derive(Deserialize)]
struct WireResponse {
    status: u16,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(default)]
    body: String,
}

/// Serializes the input document for one invocation. `config` is the
/// plugin's pre-serialized configuration JSON.
pub(crate) fn encode_input(
    call: &HookInvocation<'_>,
    config: &RawValue,
) -> Result<Vec<u8>, String> {
    let input = WireInput {
        abi_version: ABI_VERSION,
        hook: call.kind.as_str(),
        api_id: call.api_id,
        org_id: call.org_id,
        plugin_config: config,
        request: WireRequest {
            method: call.method.as_str(),
            path: call.path,
            query: call.query,
            headers: call
                .headers
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str(),
                        String::from_utf8_lossy(value.as_bytes()).into_owned(),
                    )
                })
                .collect(),
            client_addr: call.client_addr.map(|a| a.to_string()),
        },
        session: call.session_alias.map(|alias| WireSession { alias }),
    };
    serde_json::to_vec(&input).map_err(|e| format!("failed to serialize hook input: {e}"))
}

/// Parses and validates the guest's output document into a [`HookOutcome`].
pub(crate) fn decode_output(bytes: &[u8]) -> Result<HookOutcome, String> {
    let output: WireOutput = serde_json::from_slice(bytes)
        .map_err(|e| format!("guest returned invalid output JSON: {e}"))?;
    match output {
        WireOutput::Continue {
            set_headers,
            remove_headers,
        } => Ok(HookOutcome::Continue {
            set_headers: set_headers
                .iter()
                .map(|(name, value)| parse_header(name, value))
                .collect::<Result<_, _>>()?,
            remove_headers: remove_headers
                .iter()
                .map(|name| parse_header_name(name))
                .collect::<Result<_, _>>()?,
        }),
        WireOutput::Respond { response } => {
            if !(100..=599).contains(&response.status) {
                return Err(format!(
                    "guest returned invalid response status {}",
                    response.status
                ));
            }
            let status = StatusCode::from_u16(response.status).map_err(|_| {
                format!("guest returned invalid response status {}", response.status)
            })?;
            let mut resp = Response::new(Bytes::from(response.body));
            *resp.status_mut() = status;
            for (name, value) in &response.headers {
                let (name, value) = parse_header(name, value)?;
                resp.headers_mut().append(name, value);
            }
            Ok(HookOutcome::Respond(resp))
        }
    }
}

fn parse_header_name(name: &str) -> Result<HeaderName, String> {
    HeaderName::try_from(name).map_err(|_| format!("guest returned invalid header name `{name}`"))
}

fn parse_header(name: &str, value: &str) -> Result<(HeaderName, HeaderValue), String> {
    Ok((
        parse_header_name(name)?,
        HeaderValue::try_from(value)
            .map_err(|_| format!("guest returned invalid header value for `{name}`"))?,
    ))
}

#[cfg(test)]
mod tests {
    use g2_middleware::HookKind;
    use http::{HeaderMap, Method};

    use super::*;

    fn invocation<'a>(headers: &'a HeaderMap, config: &'a str) -> (HookInvocation<'a>, &'a str) {
        (
            HookInvocation {
                kind: HookKind::Pre,
                api_id: "users",
                org_id: "default",
                method: &Method::GET,
                path: "/users/1",
                query: Some("page=2"),
                headers,
                client_addr: Some("203.0.113.9:41200".parse().expect("addr")),
                session_alias: None,
            },
            config,
        )
    }

    #[test]
    fn input_encodes_every_field() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        headers.append("x-multi", HeaderValue::from_static("a"));
        headers.append("x-multi", HeaderValue::from_static("b"));
        let raw = serde_json::value::RawValue::from_string(r#"{"k":1}"#.to_owned()).expect("raw");
        let (call, _) = invocation(&headers, "");
        let encoded = encode_input(&call, &raw).expect("encode");
        let parsed: serde_json::Value = serde_json::from_slice(&encoded).expect("json");
        assert_eq!(parsed["abi_version"], 1);
        assert_eq!(parsed["hook"], "pre");
        assert_eq!(parsed["api_id"], "users");
        assert_eq!(parsed["plugin_config"], serde_json::json!({"k":1}));
        assert_eq!(parsed["request"]["method"], "GET");
        assert_eq!(parsed["request"]["path"], "/users/1");
        assert_eq!(parsed["request"]["query"], "page=2");
        assert_eq!(parsed["request"]["client_addr"], "203.0.113.9:41200");
        assert_eq!(parsed["session"], serde_json::Value::Null);
        let headers = parsed["request"]["headers"].as_array().expect("array");
        assert!(headers.contains(&serde_json::json!(["host", "example.com"])));
        // Multi-valued headers arrive as repeated pairs.
        assert!(headers.contains(&serde_json::json!(["x-multi", "a"])));
        assert!(headers.contains(&serde_json::json!(["x-multi", "b"])));
    }

    #[test]
    fn session_alias_is_encoded_when_present() {
        let headers = HeaderMap::new();
        let raw = serde_json::value::RawValue::from_string("null".to_owned()).expect("raw");
        let (mut call, _) = invocation(&headers, "");
        call.session_alias = Some("acme");
        let parsed: serde_json::Value =
            serde_json::from_slice(&encode_input(&call, &raw).expect("encode")).expect("json");
        assert_eq!(parsed["session"]["alias"], "acme");
    }

    #[test]
    fn continue_output_decodes_with_defaults() {
        let outcome = decode_output(br#"{"action":"continue"}"#).expect("decode");
        match outcome {
            HookOutcome::Continue {
                set_headers,
                remove_headers,
            } => {
                assert!(set_headers.is_empty());
                assert!(remove_headers.is_empty());
            }
            HookOutcome::Respond(_) => panic!("expected continue"),
        }
    }

    #[test]
    fn continue_output_decodes_header_mutations() {
        let outcome = decode_output(
            br#"{"action":"continue","set_headers":[["x-user","42"]],"remove_headers":["x-internal"]}"#,
        )
        .expect("decode");
        match outcome {
            HookOutcome::Continue {
                set_headers,
                remove_headers,
            } => {
                assert_eq!(set_headers.len(), 1);
                assert_eq!(set_headers[0].0.as_str(), "x-user");
                assert_eq!(set_headers[0].1, "42");
                assert_eq!(remove_headers[0].as_str(), "x-internal");
            }
            HookOutcome::Respond(_) => panic!("expected continue"),
        }
    }

    #[test]
    fn respond_output_decodes_into_a_response() {
        let outcome = decode_output(
            br#"{"action":"respond","response":{"status":403,"headers":[["content-type","text/plain"]],"body":"denied"}}"#,
        )
        .expect("decode");
        match outcome {
            HookOutcome::Respond(resp) => {
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
                assert_eq!(
                    resp.headers().get("content-type").expect("ct"),
                    "text/plain"
                );
                assert_eq!(resp.body().as_ref(), b"denied");
            }
            HookOutcome::Continue { .. } => panic!("expected respond"),
        }
    }

    #[test]
    fn malformed_outputs_are_rejected() {
        for (bytes, needle) in [
            (&b"not json"[..], "invalid output JSON"),
            (br#"{"action":"explode"}"#, "invalid output JSON"),
            (br#"{"action":"respond"}"#, "invalid output JSON"),
            (
                br#"{"action":"respond","response":{"status":42}}"#,
                "invalid response status 42",
            ),
            (
                br#"{"action":"respond","response":{"status":600}}"#,
                "invalid response status 600",
            ),
            (
                br#"{"action":"continue","set_headers":[["bad name","v"]]}"#,
                "invalid header name",
            ),
            (
                br#"{"action":"continue","set_headers":[["x-ok","bad\nvalue"]]}"#,
                "invalid header value",
            ),
            (
                br#"{"action":"continue","remove_headers":["bad name"]}"#,
                "invalid header name",
            ),
        ] {
            let err = decode_output(bytes).expect_err("must reject");
            assert!(err.contains(needle), "{err} (expected `{needle}`)");
        }
    }
}
