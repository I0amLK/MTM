//! Package-local Rust fixtures for all 135 inputs of the retired policy corpus.
//! Expectations are explicit, not obtained by running the implementation or Python.
//! The numeric lower-bound defect is intentionally corrected. Error messages must
//! be nonempty, but their old Python spelling is not the current contract.
use serde_json::{Value, json};

pub struct Case {
    pub name: String,
    pub request: Value,
    expected: Value,
}

impl Case {
    pub fn matches(&self, actual: &Value) -> bool {
        let mut projected = actual.clone();
        if projected["ok"] == false {
            let Some(error) = projected.get_mut("error").and_then(Value::as_object_mut) else {
                return false;
            };
            if !error
                .remove("message")
                .is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty()))
            {
                return false;
            }
        }
        projected == self.expected
    }
}

fn add(cases: &mut Vec<Case>, name: &str, op: &str, mut request: Value, expected: Value) {
    request["operation"] = json!(op);
    cases.push(Case {
        name: name.to_owned(),
        request,
        expected,
    });
}

fn pass(value: Value) -> Value {
    json!({"ok":true,"result":value})
}

fn fail(code: &str, category: &str, retryable: bool, details: Value) -> Value {
    json!({"ok":false,"error":{"code":code,"category":category,"retryable":retryable,"details":details}})
}

fn invalid(code: &str) -> Value {
    fail(code, "validation", false, json!({}))
}

pub fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    basic(&mut out);
    schemas(&mut out);
    urls(&mut out);
    paths(&mut out);
    commands(&mut out);
    patches(&mut out);
    out
}

fn basic(out: &mut Vec<Case>) {
    for (state, terminal) in [
        ("created", false),
        ("verify", false),
        ("done", true),
        ("cancelled", true),
        ("failed", true),
    ] {
        add(
            out,
            &format!("workflow-terminal-{state}"),
            "workflow_terminal",
            json!({"value":state}),
            pass(json!(terminal)),
        );
    }
    for (name, text, expected) in [
        ("fingerprint-ascii", "abc", "ba7816bf8f01"),
        ("fingerprint-unicode", "数学-proof", "f83a77ffb698"),
    ] {
        add(
            out,
            name,
            "fingerprint",
            json!({"value":text}),
            pass(json!(expected)),
        );
    }
    add(
        out,
        "redact-bytes",
        "redact_bytes",
        json!({"value":"abc"}),
        pass(json!("<bytes:3:ba7816bf8f01>")),
    );
    add(
        out,
        "redact-nested",
        "redact",
        json!({"value":{
            "password":"plain","safe":"visible","nested":[{"API_Key":"value"},"Bearer abc.def-123"]
        }}),
        pass(
            json!({"password":"<redacted>","safe":"visible","nested":[{"API_Key":"<redacted>"},"<redacted>"]}),
        ),
    );
    for (name, value, expected) in [
        (
            "redact-sk-value",
            "prefix sk-abcdefghijkl suffix",
            "prefix <redacted> suffix",
        ),
        (
            "redact-private-key",
            "-----BEGIN RSA PRIVATE KEY----- payload",
            "<redacted> payload",
        ),
        ("redact-short-sk-not-secret", "sk-short", "sk-short"),
    ] {
        add(
            out,
            name,
            "redact",
            json!({"value":value}),
            pass(json!(expected)),
        );
    }
}

fn schemas(out: &mut Vec<Case>) {
    let object = json!({"type":"object","required":["name"],"additionalProperties":false,
        "properties":{"name":{"type":"string","minLength":1,"maxLength":4},
        "count":{"type":"integer","minimum":1,"maximum":3}}});
    let mut entries = vec![
        (
            "schema-object-valid",
            json!({"name":"abc","count":2}),
            object.clone(),
            true,
        ),
        ("schema-missing-required", json!({}), object.clone(), false),
        (
            "schema-extra-field",
            json!({"name":"x","extra":true}),
            object.clone(),
            false,
        ),
        (
            "schema-min-length",
            json!({"name":""}),
            object.clone(),
            false,
        ),
        (
            "schema-max-length",
            json!({"name":"abcde"}),
            object.clone(),
            false,
        ),
        (
            "schema-minimum",
            json!({"name":"x","count":0}),
            object.clone(),
            false,
        ),
        (
            "schema-maximum",
            json!({"name":"x","count":4}),
            object,
            false,
        ),
        (
            "schema-bool-not-integer",
            json!(true),
            json!({"type":"integer"}),
            false,
        ),
        // This old input previously bypassed minimum. Preserve input, not the bug.
        (
            "schema-float-number",
            json!(1.5),
            json!({"type":"number","minimum":3}),
            false,
        ),
        (
            "schema-pattern-valid",
            json!("abc"),
            json!({"type":"string","pattern":"[a-z]+"}),
            true,
        ),
        (
            "schema-pattern-invalid",
            json!("abc1"),
            json!({"type":"string","pattern":"[a-z]+"}),
            false,
        ),
        (
            "schema-enum-valid",
            json!("a"),
            json!({"type":"string","enum":["a","b"]}),
            true,
        ),
        (
            "schema-enum-invalid",
            json!("c"),
            json!({"type":"string","enum":["a","b"]}),
            false,
        ),
        (
            "schema-const-valid",
            json!("go"),
            json!({"const":"go"}),
            true,
        ),
        (
            "schema-const-invalid",
            json!("stop"),
            json!({"const":"go"}),
            false,
        ),
        (
            "schema-type-union-valid",
            Value::Null,
            json!({"type":["string","null"]}),
            true,
        ),
        (
            "schema-type-union-invalid",
            json!(2),
            json!({"type":["string","null"]}),
            false,
        ),
        (
            "schema-array-valid",
            json!([1, 2]),
            json!({"type":"array","minItems":2,"items":{"type":"integer"}}),
            true,
        ),
        (
            "schema-array-too-short",
            json!([1]),
            json!({"type":"array","minItems":2}),
            false,
        ),
        (
            "schema-array-item-invalid",
            json!([1, true]),
            json!({"type":"array","items":{"type":"integer"}}),
            false,
        ),
    ];
    let one =
        json!({"oneOf":[{"type":"object","required":["a"]},{"type":"object","required":["b"]}]});
    let any = json!({"anyOf":[{"type":"string"},{"type":"integer"}]});
    let additional = json!({"type":"object","additionalProperties":{"type":"integer"}});
    entries.extend([
        ("schema-one-of-valid", json!({"a":1}), one.clone(), true),
        (
            "schema-one-of-two",
            json!({"a":1,"b":2}),
            one.clone(),
            false,
        ),
        ("schema-one-of-zero", json!({}), one, false),
        ("schema-any-of-valid", json!(3), any.clone(), true),
        ("schema-any-of-invalid", json!(false), any, false),
        (
            "schema-additional-schema-valid",
            json!({"x":2}),
            additional.clone(),
            true,
        ),
        (
            "schema-additional-schema-invalid",
            json!({"x":"bad"}),
            additional,
            false,
        ),
    ]);
    for (name, value, schema, allowed) in entries {
        let expected = if allowed {
            pass(json!({"valid":true}))
        } else {
            invalid("INVALID_ARGUMENT")
        };
        add(
            out,
            name,
            "schema_validate",
            json!({"value":value,"schema":schema}),
            expected,
        );
    }
}

fn urls(out: &mut Vec<Case>) {
    for (name, value, allowed) in [
        ("oauth-https", "https://example.com", true),
        ("oauth-https-slash", "https://example.com/", true),
        ("oauth-loopback-v4", "http://127.0.0.1:8765", true),
        ("oauth-loopback-name", "http://localhost:8765", true),
        ("oauth-loopback-v6", "http://[::1]:8765", true),
        ("oauth-http-public", "http://example.com", false),
        ("oauth-path", "https://example.com/path", false),
        ("oauth-query", "https://example.com?x=1", false),
        ("oauth-empty-query", "https://example.com?", true),
        ("oauth-fragment", "https://example.com#x", false),
        ("oauth-empty-fragment", "https://example.com#", true),
        ("oauth-userinfo", "https://user@example.com", false),
        ("oauth-empty-userinfo", "https://@example.com", false),
        ("oauth-ftp", "ftp://example.com", false),
        ("oauth-bad-port", "https://example.com:bad", false),
    ] {
        let expected = if allowed {
            pass(json!({"valid":true}))
        } else {
            invalid("OAUTH_SERVER_URL_INVALID")
        };
        add(
            out,
            name,
            "oauth_server_url",
            json!({"value":value}),
            expected,
        );
    }
    for (name, value, allowed) in [
        (
            "redirect-https",
            json!(["https://client.example/callback"]),
            true,
        ),
        (
            "redirect-loopback",
            json!(["http://127.0.0.1:1234/callback"]),
            true,
        ),
        ("redirect-empty", json!([]), false),
        (
            "redirect-non-list",
            json!("https://client.example/callback"),
            false,
        ),
        (
            "redirect-too-many",
            json!(
                (0..11)
                    .map(|i| format!("https://client.example/{i}"))
                    .collect::<Vec<_>>()
            ),
            false,
        ),
        (
            "redirect-fragment",
            json!(["https://client.example/callback#fragment"]),
            false,
        ),
        (
            "redirect-empty-fragment",
            json!(["https://client.example/callback#"]),
            true,
        ),
        (
            "redirect-userinfo",
            json!(["https://user@client.example/callback"]),
            false,
        ),
        (
            "redirect-empty-userinfo",
            json!(["https://@client.example/callback"]),
            false,
        ),
        (
            "redirect-public-http",
            json!(["http://client.example/callback"]),
            false,
        ),
        (
            "redirect-ftp",
            json!(["ftp://client.example/callback"]),
            false,
        ),
        (
            "redirect-duplicate",
            json!(["https://client.example/cb", "https://client.example/cb"]),
            false,
        ),
        ("redirect-non-string", json!([3]), false),
        (
            "redirect-too-long",
            json!([format!("https://client.example/{}", "a".repeat(2050))]),
            false,
        ),
    ] {
        let expected = if allowed {
            pass(value.clone())
        } else {
            invalid("INVALID_ARGUMENT")
        };
        add(out, name, "redirect_uris", json!({"value":value}), expected);
    }
    for (name, value, origin) in [
        (
            "tunnel-valid",
            "INF https://alpha-beta.trycloudflare.com connected",
            Some("https://alpha-beta.trycloudflare.com"),
        ),
        (
            "tunnel-valid-path",
            "https://alpha.trycloudflare.com/path?q=1",
            Some("https://alpha.trycloudflare.com"),
        ),
        (
            "tunnel-valid-punctuation",
            "URL=(https://alpha.trycloudflare.com),",
            Some("https://alpha.trycloudflare.com"),
        ),
        (
            "tunnel-valid-443",
            "https://alpha.trycloudflare.com:443/path",
            Some("https://alpha.trycloudflare.com"),
        ),
        (
            "tunnel-uppercase-host",
            "https://Alpha-Beta.trycloudflare.com",
            Some("https://alpha-beta.trycloudflare.com"),
        ),
        ("tunnel-http", "http://alpha.trycloudflare.com", None),
        ("tunnel-port", "https://alpha.trycloudflare.com:8443", None),
        (
            "tunnel-userinfo",
            "https://user@alpha.trycloudflare.com",
            None,
        ),
        (
            "tunnel-empty-userinfo",
            "https://@alpha.trycloudflare.com",
            None,
        ),
        (
            "tunnel-suffix-confusion",
            "https://alpha.trycloudflare.com.evil.example",
            None,
        ),
        ("tunnel-multilabel", "https://a.b.trycloudflare.com", None),
        ("tunnel-unrelated", "https://example.com", None),
    ] {
        add(
            out,
            name,
            "quick_tunnel_origin",
            json!({"value":value}),
            pass(json!(origin)),
        );
    }
}

fn paths(out: &mut Vec<Case>) {
    for (name, value, result) in [
        ("path-dot", ".", pass(json!("."))),
        ("path-normalize", "./a//b/", pass(json!("a/b"))),
        ("path-backslash", r"a\b", pass(json!(r"a\b"))),
        (
            "path-absolute",
            "/etc/passwd",
            fail("ABSOLUTE_PATH_DENIED", "security", false, json!({})),
        ),
        (
            "path-windows",
            r"C:\temp",
            fail("ABSOLUTE_PATH_DENIED", "security", false, json!({})),
        ),
        (
            "path-parent",
            "a/../b",
            fail("PATH_OUTSIDE_WORKSPACE", "security", false, json!({})),
        ),
        (
            "path-parent-leading",
            "../b",
            fail("PATH_OUTSIDE_WORKSPACE", "security", false, json!({})),
        ),
        ("path-dotdot-name", "a/..b", pass(json!("a/..b"))),
        ("path-empty", "", invalid("INVALID_ARGUMENT")),
        ("path-nul", "a\0b", invalid("INVALID_ARGUMENT")),
    ] {
        add(out, name, "workspace_path", json!({"value":value}), result);
    }
}

fn commands(out: &mut Vec<Case>) {
    for (name, key, value, filtered) in [
        ("env-api-key", "API_KEY", "plain", true),
        ("env-path", "PATH", "/usr/bin", false),
        ("env-node-options", "NODE_OPTIONS", "plain", true),
        ("env-dyld", "DYLD_FOO", "plain", true),
        ("env-sk-secret", "VALUE", "sk-abcdefghijklmnop", true),
        ("env-github-secret", "VALUE", "ghp_abcdefghijkl", true),
        ("env-aws-secret", "VALUE", "AKIAABCDEFGHIJKLMNOP", true),
        ("env-benign", "VALUE", "visible", false),
    ] {
        add(
            out,
            name,
            "filtered_env",
            json!({"name":key,"value":value}),
            pass(json!(filtered)),
        );
    }
    for (name, value, command, option) in [
        ("inline-bash-c", "bash -c 'echo hi'", "bash", "-c"),
        ("inline-sh-lc", "sh -lc 'echo hi'", "sh", "-lc"),
        ("inline-python-c", "python3 -c 'print(1)'", "python3", "-c"),
        ("inline-python-stdin", "python -", "python", "-"),
        ("inline-node-eval", "node --eval '1+1'", "node", "--eval"),
        ("inline-ruby", "ruby -e 'puts 1'", "ruby", "-e"),
        ("inline-perl", "perl -e 'print 1'", "perl", "-e"),
        (
            "inline-env",
            "env FOO=1 python3 -c 'print(1)'",
            "python3",
            "-c",
        ),
        ("inline-assignment", "FOO=1 bash -c 'echo hi'", "bash", "-c"),
        ("inline-script-file", "python3 script.py", "", ""),
        ("inline-ordinary", "printf hello", "", ""),
        (
            "inline-unbalanced-quote",
            "python3 -c 'unterminated",
            "python3",
            "-c",
        ),
    ] {
        let result = if command.is_empty() {
            Value::Null
        } else {
            json!({"command":command,"option":option})
        };
        add(
            out,
            name,
            "inline_script",
            json!({"value":value}),
            pass(result),
        );
    }
    for (name, mode, command, env, permission) in [
        ("policy-safe-normal", "safe", "printf hello", json!({}), ""),
        (
            "policy-safe-network",
            "safe",
            "curl https://example.com",
            json!({}),
            "network",
        ),
        (
            "policy-safe-shell-expansion",
            "safe",
            "echo $(pwd)",
            json!({}),
            "shell_expansion",
        ),
        (
            "policy-safe-inline",
            "safe",
            "python3 -c 'print(1)'",
            json!({}),
            "inline_script",
        ),
        (
            "policy-safe-destructive",
            "safe",
            "rm -rf build",
            json!({}),
            "destructive_command",
        ),
        (
            "policy-safe-sensitive-env",
            "safe",
            "printf hi",
            json!({"API_TOKEN":"x"}),
            "sensitive_env",
        ),
        (
            "policy-order-env-before-destructive",
            "safe",
            "rm -rf build",
            json!({"API_TOKEN":"x"}),
            "sensitive_env",
        ),
        (
            "policy-trusted-network",
            "trusted",
            "curl https://example.com",
            json!({}),
            "",
        ),
        (
            "policy-trusted-inline",
            "trusted",
            "python3 -c 'print(1)'",
            json!({}),
            "",
        ),
        (
            "policy-trusted-destructive",
            "trusted",
            "rm -rf build",
            json!({}),
            "destructive_command",
        ),
        (
            "policy-dangerous-allows",
            "dangerous",
            "rm -rf /",
            json!({"API_TOKEN":"x"}),
            "",
        ),
    ] {
        // MTM-017 retired the safe/trusted modes: their frozen inputs are now
        // rejected as invalid; the risk they named is only classified, never
        // enforced, under the dangerous profile.
        let _classified_risk = permission;
        let expected = if mode == "dangerous" {
            pass(json!({"allowed":true}))
        } else {
            invalid("INVALID_ARGUMENT")
        };
        add(
            out,
            name,
            "command_policy",
            json!({"mode":mode,"command":command,"env":env}),
            expected,
        );
    }
}

fn patches(out: &mut Vec<Case>) {
    for (name, input, result) in [
        (
            "patch-invalid-envelope",
            "not a patch",
            invalid("PATCH_FAILED"),
        ),
        (
            "patch-add",
            "*** Begin Patch\n*** Add File: a.txt\n+hello\n+world\n*** End Patch\n",
            pass(
                json!([{"kind":"add","path":"a.txt","add_content":"hello\nworld\n","hunks":[],"move_to":null}]),
            ),
        ),
        (
            "patch-add-bad-line",
            "*** Begin Patch\n*** Add File: a.txt\nhello\n*** End Patch\n",
            invalid("PATCH_FAILED"),
        ),
        (
            "patch-delete",
            "*** Begin Patch\n*** Delete File: old.txt\n*** End Patch\n",
            pass(
                json!([{"kind":"delete","path":"old.txt","add_content":null,"hunks":[],"move_to":null}]),
            ),
        ),
        (
            "patch-update",
            "*** Begin Patch\n*** Update File: a.txt\n@@\n-old\n+new\n*** End Patch\n",
            pass(
                json!([{"kind":"update","path":"a.txt","add_content":null,"hunks":[["-old","+new"]],"move_to":null}]),
            ),
        ),
        (
            "patch-move",
            "*** Begin Patch\n*** Update File: a.txt\n*** Move to: b.txt\n@@\n old\n*** End Patch\n",
            pass(
                json!([{"kind":"update","path":"a.txt","add_content":null,"hunks":[[" old"]],"move_to":"b.txt"}]),
            ),
        ),
        (
            "patch-unrecognized",
            "*** Begin Patch\n*** Unknown: a.txt\n*** End Patch\n",
            invalid("PATCH_FAILED"),
        ),
    ] {
        add(out, name, "parse_patch", json!({"value":input}), result);
    }
    for (name, content, hunks, result) in [
        (
            "hunks-none",
            "unchanged\n",
            json!([]),
            pass(json!("unchanged\n")),
        ),
        (
            "hunks-valid",
            "one\ntwo\n",
            json!([[" one", "-two", "+changed"]]),
            pass(json!("one\nchanged\n")),
        ),
        (
            "hunks-crlf",
            "one\r\ntwo\r\n",
            json!([[" one", "-two", "+changed"]]),
            pass(json!("one\r\nchanged\r\n")),
        ),
        (
            "hunks-not-found",
            "one\n",
            json!([[" missing"]]),
            fail(
                "PATCH_CONTEXT_NOT_FOUND",
                "validation",
                true,
                json!({"hunk_index":0}),
            ),
        ),
        (
            "hunks-ambiguous",
            "same\nsame\n",
            json!([[" same", "+x"]]),
            fail(
                "PATCH_CONTEXT_AMBIGUOUS",
                "validation",
                true,
                json!({"hunk_index":0,"match_count":2}),
            ),
        ),
        (
            "hunks-invalid-marker",
            "one\n",
            json!([["?one"]]),
            invalid("PATCH_FAILED"),
        ),
        (
            "hunks-overlap",
            "a\nb\nc\n",
            json!([[" a", " b"], [" b", " c"]]),
            invalid("PATCH_HUNKS_OVERLAP"),
        ),
    ] {
        add(
            out,
            name,
            "apply_hunks",
            json!({"content":content,"hunks":hunks,"path":"a.txt"}),
            result,
        );
    }
}
