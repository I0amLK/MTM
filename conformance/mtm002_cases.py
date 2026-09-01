from __future__ import annotations

from typing import Any


def cases() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []

    def add(case_name: str, operation: str, **payload: Any) -> None:
        result.append({"name": case_name, "request": {"operation": operation, **payload}})

    for state, expected_terminal in (
        ("created", False),
        ("verify", False),
        ("done", True),
        ("cancelled", True),
        ("failed", True),
    ):
        add(f"workflow-terminal-{state}", "workflow_terminal", value=state)

    add("fingerprint-ascii", "fingerprint", value="abc")
    add("fingerprint-unicode", "fingerprint", value="数学-proof")
    add("redact-bytes", "redact_bytes", value="abc")
    add(
        "redact-nested",
        "redact",
        value={
            "password": "plain",
            "safe": "visible",
            "nested": [{"API_Key": "value"}, "Bearer abc.def-123"],
        },
    )
    add("redact-sk-value", "redact", value="prefix sk-abcdefghijkl suffix")
    add(
        "redact-private-key",
        "redact",
        value="-----BEGIN RSA PRIVATE KEY----- payload",
    )
    add("redact-short-sk-not-secret", "redact", value="sk-short")

    object_schema = {
        "type": "object",
        "required": ["name"],
        "additionalProperties": False,
        "properties": {
            "name": {"type": "string", "minLength": 1, "maxLength": 4},
            "count": {"type": "integer", "minimum": 1, "maximum": 3},
        },
    }
    add("schema-object-valid", "schema_validate", value={"name": "abc", "count": 2}, schema=object_schema)
    add("schema-missing-required", "schema_validate", value={}, schema=object_schema)
    add("schema-extra-field", "schema_validate", value={"name": "x", "extra": True}, schema=object_schema)
    add("schema-min-length", "schema_validate", value={"name": ""}, schema=object_schema)
    add("schema-max-length", "schema_validate", value={"name": "abcde"}, schema=object_schema)
    add("schema-minimum", "schema_validate", value={"name": "x", "count": 0}, schema=object_schema)
    add("schema-maximum", "schema_validate", value={"name": "x", "count": 4}, schema=object_schema)
    add("schema-bool-not-integer", "schema_validate", value=True, schema={"type": "integer"})
    add("schema-float-number", "schema_validate", value=1.5, schema={"type": "number", "minimum": 3})
    add("schema-pattern-valid", "schema_validate", value="abc", schema={"type": "string", "pattern": "[a-z]+"})
    add("schema-pattern-invalid", "schema_validate", value="abc1", schema={"type": "string", "pattern": "[a-z]+"})
    add("schema-enum-valid", "schema_validate", value="a", schema={"type": "string", "enum": ["a", "b"]})
    add("schema-enum-invalid", "schema_validate", value="c", schema={"type": "string", "enum": ["a", "b"]})
    add("schema-const-valid", "schema_validate", value="go", schema={"const": "go"})
    add("schema-const-invalid", "schema_validate", value="stop", schema={"const": "go"})
    add("schema-type-union-valid", "schema_validate", value=None, schema={"type": ["string", "null"]})
    add("schema-type-union-invalid", "schema_validate", value=2, schema={"type": ["string", "null"]})
    add("schema-array-valid", "schema_validate", value=[1, 2], schema={"type": "array", "minItems": 2, "items": {"type": "integer"}})
    add("schema-array-too-short", "schema_validate", value=[1], schema={"type": "array", "minItems": 2})
    add("schema-array-item-invalid", "schema_validate", value=[1, True], schema={"type": "array", "items": {"type": "integer"}})
    add("schema-one-of-valid", "schema_validate", value={"a": 1}, schema={"oneOf": [{"type": "object", "required": ["a"]}, {"type": "object", "required": ["b"]}]})
    add("schema-one-of-two", "schema_validate", value={"a": 1, "b": 2}, schema={"oneOf": [{"type": "object", "required": ["a"]}, {"type": "object", "required": ["b"]}]})
    add("schema-one-of-zero", "schema_validate", value={}, schema={"oneOf": [{"type": "object", "required": ["a"]}, {"type": "object", "required": ["b"]}]})
    add("schema-any-of-valid", "schema_validate", value=3, schema={"anyOf": [{"type": "string"}, {"type": "integer"}]})
    add("schema-any-of-invalid", "schema_validate", value=False, schema={"anyOf": [{"type": "string"}, {"type": "integer"}]})
    add("schema-additional-schema-valid", "schema_validate", value={"x": 2}, schema={"type": "object", "additionalProperties": {"type": "integer"}})
    add("schema-additional-schema-invalid", "schema_validate", value={"x": "bad"}, schema={"type": "object", "additionalProperties": {"type": "integer"}})

    for name, value in (
        ("oauth-https", "https://example.com"),
        ("oauth-https-slash", "https://example.com/"),
        ("oauth-loopback-v4", "http://127.0.0.1:8765"),
        ("oauth-loopback-name", "http://localhost:8765"),
        ("oauth-loopback-v6", "http://[::1]:8765"),
        ("oauth-http-public", "http://example.com"),
        ("oauth-path", "https://example.com/path"),
        ("oauth-query", "https://example.com?x=1"),
        ("oauth-empty-query", "https://example.com?"),
        ("oauth-fragment", "https://example.com#x"),
        ("oauth-empty-fragment", "https://example.com#"),
        ("oauth-userinfo", "https://user@example.com"),
        ("oauth-empty-userinfo", "https://@example.com"),
        ("oauth-ftp", "ftp://example.com"),
        ("oauth-bad-port", "https://example.com:bad"),
    ):
        add(name, "oauth_server_url", value=value)

    add("redirect-https", "redirect_uris", value=["https://client.example/callback"])
    add("redirect-loopback", "redirect_uris", value=["http://127.0.0.1:1234/callback"])
    add("redirect-empty", "redirect_uris", value=[])
    add("redirect-non-list", "redirect_uris", value="https://client.example/callback")
    add("redirect-too-many", "redirect_uris", value=[f"https://client.example/{index}" for index in range(11)])
    add("redirect-fragment", "redirect_uris", value=["https://client.example/callback#fragment"])
    add("redirect-empty-fragment", "redirect_uris", value=["https://client.example/callback#"])
    add("redirect-userinfo", "redirect_uris", value=["https://user@client.example/callback"])
    add("redirect-empty-userinfo", "redirect_uris", value=["https://@client.example/callback"])
    add("redirect-public-http", "redirect_uris", value=["http://client.example/callback"])
    add("redirect-ftp", "redirect_uris", value=["ftp://client.example/callback"])
    add("redirect-duplicate", "redirect_uris", value=["https://client.example/cb", "https://client.example/cb"])
    add("redirect-non-string", "redirect_uris", value=[3])
    add("redirect-too-long", "redirect_uris", value=["https://client.example/" + "a" * 2050])

    for name, value in (
        ("tunnel-valid", "INF https://alpha-beta.trycloudflare.com connected"),
        ("tunnel-valid-path", "https://alpha.trycloudflare.com/path?q=1"),
        ("tunnel-valid-punctuation", "URL=(https://alpha.trycloudflare.com),"),
        ("tunnel-valid-443", "https://alpha.trycloudflare.com:443/path"),
        ("tunnel-uppercase-host", "https://Alpha-Beta.trycloudflare.com"),
        ("tunnel-http", "http://alpha.trycloudflare.com"),
        ("tunnel-port", "https://alpha.trycloudflare.com:8443"),
        ("tunnel-userinfo", "https://user@alpha.trycloudflare.com"),
        ("tunnel-empty-userinfo", "https://@alpha.trycloudflare.com"),
        ("tunnel-suffix-confusion", "https://alpha.trycloudflare.com.evil.example"),
        ("tunnel-multilabel", "https://a.b.trycloudflare.com"),
        ("tunnel-unrelated", "https://example.com"),
    ):
        add(name, "quick_tunnel_origin", value=value)

    for name, value in (
        ("path-dot", "."),
        ("path-normalize", "./a//b/"),
        ("path-backslash", r"a\b"),
        ("path-absolute", "/etc/passwd"),
        ("path-windows", r"C:\temp"),
        ("path-parent", "a/../b"),
        ("path-parent-leading", "../b"),
        ("path-dotdot-name", "a/..b"),
        ("path-empty", ""),
        ("path-nul", "a\u0000b"),
    ):
        add(name, "workspace_path", value=value)

    for name, env_name, value in (
        ("env-api-key", "API_KEY", "plain"),
        ("env-path", "PATH", "/usr/bin"),
        ("env-node-options", "NODE_OPTIONS", "plain"),
        ("env-dyld", "DYLD_FOO", "plain"),
        ("env-sk-secret", "VALUE", "sk-abcdefghijklmnop"),
        ("env-github-secret", "VALUE", "ghp_abcdefghijkl"),
        ("env-aws-secret", "VALUE", "AKIAABCDEFGHIJKLMNOP"),
        ("env-benign", "VALUE", "visible"),
    ):
        add(name, "filtered_env", name=env_name, value=value)

    for name, value in (
        ("inline-bash-c", "bash -c 'echo hi'"),
        ("inline-sh-lc", "sh -lc 'echo hi'"),
        ("inline-python-c", "python3 -c 'print(1)'"),
        ("inline-python-stdin", "python -"),
        ("inline-node-eval", "node --eval '1+1'"),
        ("inline-ruby", "ruby -e 'puts 1'"),
        ("inline-perl", "perl -e 'print 1'"),
        ("inline-env", "env FOO=1 python3 -c 'print(1)'"),
        ("inline-assignment", "FOO=1 bash -c 'echo hi'"),
        ("inline-script-file", "python3 script.py"),
        ("inline-ordinary", "printf hello"),
        ("inline-unbalanced-quote", "python3 -c 'unterminated"),
    ):
        add(name, "inline_script", value=value)

    add("policy-safe-normal", "command_policy", mode="safe", command="printf hello", env={})
    add("policy-safe-network", "command_policy", mode="safe", command="curl https://example.com", env={})
    add("policy-safe-shell-expansion", "command_policy", mode="safe", command="echo $(pwd)", env={})
    add("policy-safe-inline", "command_policy", mode="safe", command="python3 -c 'print(1)'", env={})
    add("policy-safe-destructive", "command_policy", mode="safe", command="rm -rf build", env={})
    add("policy-safe-sensitive-env", "command_policy", mode="safe", command="printf hi", env={"API_TOKEN": "x"})
    add("policy-order-env-before-destructive", "command_policy", mode="safe", command="rm -rf build", env={"API_TOKEN": "x"})
    add("policy-trusted-network", "command_policy", mode="trusted", command="curl https://example.com", env={})
    add("policy-trusted-inline", "command_policy", mode="trusted", command="python3 -c 'print(1)'", env={})
    add("policy-trusted-destructive", "command_policy", mode="trusted", command="rm -rf build", env={})
    add("policy-dangerous-allows", "command_policy", mode="dangerous", command="rm -rf /", env={"API_TOKEN": "x"})

    add("patch-invalid-envelope", "parse_patch", value="not a patch")
    add("patch-add", "parse_patch", value="*** Begin Patch\n*** Add File: a.txt\n+hello\n+world\n*** End Patch\n")
    add("patch-add-bad-line", "parse_patch", value="*** Begin Patch\n*** Add File: a.txt\nhello\n*** End Patch\n")
    add("patch-delete", "parse_patch", value="*** Begin Patch\n*** Delete File: old.txt\n*** End Patch\n")
    add("patch-update", "parse_patch", value="*** Begin Patch\n*** Update File: a.txt\n@@\n-old\n+new\n*** End Patch\n")
    add("patch-move", "parse_patch", value="*** Begin Patch\n*** Update File: a.txt\n*** Move to: b.txt\n@@\n old\n*** End Patch\n")
    add("patch-unrecognized", "parse_patch", value="*** Begin Patch\n*** Unknown: a.txt\n*** End Patch\n")

    add("hunks-none", "apply_hunks", content="unchanged\n", hunks=[], path="a.txt")
    add("hunks-valid", "apply_hunks", content="one\ntwo\n", hunks=[[" one", "-two", "+changed"]], path="a.txt")
    add("hunks-crlf", "apply_hunks", content="one\r\ntwo\r\n", hunks=[[" one", "-two", "+changed"]], path="a.txt")
    add("hunks-not-found", "apply_hunks", content="one\n", hunks=[[" missing"]], path="a.txt")
    add("hunks-ambiguous", "apply_hunks", content="same\nsame\n", hunks=[[" same", "+x"]], path="a.txt")
    add("hunks-invalid-marker", "apply_hunks", content="one\n", hunks=[["?one"]], path="a.txt")
    add("hunks-overlap", "apply_hunks", content="a\nb\nc\n", hunks=[[" a", " b"], [" b", " c"]], path="a.txt")

    return result
