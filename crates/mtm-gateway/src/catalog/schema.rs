//! Concrete, model-visible schemas built from the MTM registry.
use serde_json::{Map, Value, json};

use super::{ToolId, workflow_schema};

pub(super) fn object(properties: Value, required: &[&str]) -> Value {
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}

pub(super) fn text() -> Value {
    json!({"type":"string"})
}

pub(super) fn nonempty() -> Value {
    json!({"type":"string","minLength":1})
}

pub(super) fn strings() -> Value {
    json!({"type":"array","items":text()})
}

pub(super) fn integer(min: u64, max: u64, default: u64) -> Value {
    json!({"type":"integer","minimum":min,"maximum":max,"default":default})
}

pub(super) fn boolean(default: bool) -> Value {
    json!({"type":"boolean","default":default})
}

pub(super) fn choice(values: &[&str]) -> Value {
    json!({"type":"string","enum":values})
}

pub(super) fn output(id: ToolId) -> Value {
    let mut schema = output_base();
    if let Some(properties) = schema["properties"].as_object_mut() {
        properties.extend(native_output::properties(id));
    }
    schema
}

#[path = "native_output.rs"]
mod native_output;

fn output_base() -> Value {
    json!({"type":"object","required":["ok"],"additionalProperties":true,
    "properties":{"ok":{"type":"boolean"},"error":{
        "type":"object","additionalProperties":true,
        "required":["code","message","category","retryable","details"],
        "properties":{"code":text(),"message":text(),"category":text(),
            "retryable":{"type":"boolean"},"details":{"type":"object","additionalProperties":true}}
    }}})
}

fn output_options(mut properties: Map<String, Value>) -> Value {
    properties.insert("max_output_bytes".to_owned(), integer(1, 1_048_576, 65_536));
    properties.insert("preview_bytes".to_owned(), integer(1, 1_048_576, 4096));
    properties.insert(
        "verbosity".to_owned(),
        choice(&["summary", "preview", "full"]),
    );
    Value::Object(properties)
}

pub(super) fn input(id: ToolId) -> Value {
    use ToolId as T;
    match id {
        T::ServerInfo | T::CheckExecEnvironment => object(json!({}), &[]),
        T::ReadFile => object(
            json!({
                "path":{"type":"string","minLength":1,"description":"Workspace-relative file path, for example README.md or nested/file.txt. Absolute host paths, including paths formed from server_info.workspace, are rejected."}, "encoding":{"type":"string","enum":["utf-8"],"default":"utf-8"},
                "start_line":{"type":"integer","minimum":1,"default":1},
                "end_line":{"type":"integer","minimum":1},"max_lines":{"type":"integer","minimum":1},
                "line_byte_offset":integer(0,67_108_864,0),
                "expected_sha256":{"type":"string","pattern":"[0-9a-f]{64}"},
                "max_bytes":integer(1,1_048_576,131_072)
            }),
            &["path"],
        ),
        T::ListDir => object(
            json!({
                "path":{"type":"string","default":"."},"recursive":boolean(false),
                "include_hidden":boolean(false),"include_ignored":boolean(false),
                "max_depth":integer(1,20,1),"max_entries":integer(1,10_000,1000),
                "sort":{"type":"string","enum":["name","type","modified"],"default":"name"}
            }),
            &[],
        ),
        T::ListFiles => object(
            json!({
                "path":{"type":"string","default":"."},"patterns":strings(),"glob":text(),
                "exclude_patterns":strings(),"include_hidden":boolean(false),"include_ignored":boolean(false),
                "max_results":integer(1,50_000,5000),
                "sort":{"type":"string","enum":["path","modified"],"default":"path"}
            }),
            &[],
        ),
        T::SearchText => object(
            json!({
                "path":{"type":"string","default":".","description":"Workspace file or directory."},
                "query":nonempty(),"regex":boolean(false),"case_sensitive":boolean(false),
                "include_globs":strings(),"exclude_globs":strings(),"glob":text(),
                "context_lines":integer(0,5,0),"max_results":integer(1,10_000,1000),
                "max_preview_bytes":integer(80,4096,512)
            }),
            &["query"],
        ),
        T::ApplyPatch => object(
            json!({"patch":nonempty(),"dry_run":boolean(false),"idempotency_key":{"type":"string","minLength":1,"maxLength":128}}),
            &["patch"],
        ),
        T::ApplyChanges => object(
            json!({
                "changes":{"type":"array","minItems":1,"maxItems":100,"items":object(json!({
                    "action":choice(&["create","write","edit","delete","move","copy"]),
                    "path":nonempty(),"content":text(),"destination":nonempty(),
                    "revision":{"type":"string","pattern":"^[0-9a-fA-F]{64}$"},
                    "edits":{"type":"array","minItems":1,"maxItems":200,"items":object(json!({
                        "op":choice(&["replace","delete","insert_after","insert_before"]),
                        "start_line":{"type":"integer","minimum":1},"end_line":{"type":"integer","minimum":1},
                        "line":{"type":"integer","minimum":0},"content":text()
                    }), &["op"])}
                }), &["action","path"])},
                "dry_run":boolean(false),"idempotency_key":{"type":"string","minLength":1,"maxLength":128}
            }),
            &["changes"],
        ),
        T::ExecCommand => {
            let properties = output_options(Map::from_iter([
                ("cmd".to_owned(), nonempty()),
                (
                    "argv".to_owned(),
                    json!({"type":"array","minItems":1,"items":nonempty(),"description":"Literal executable and arguments, without a shell. Arguments may be empty except argv[0], which the runtime validates."}),
                ),
                (
                    "workdir".to_owned(),
                    json!({"type":"string","default":".","description":"Workspace-relative working directory. Use . for the workspace root. Do not pass the absolute host path reported by server_info.workspace."}),
                ),
                (
                    "cwd".to_owned(),
                    json!({"type":"string","description":"Legacy alias for workdir; when supplied it is also workspace-relative. Use . for the workspace root, never an absolute host path."}),
                ),
                (
                    "env".to_owned(),
                    json!({"type":"object","additionalProperties":{"type":"string"},"default":{}}),
                ),
                ("stdin".to_owned(), json!({"type":"string","default":""})),
                ("tty".to_owned(), boolean(false)),
                ("timeout_ms".to_owned(), integer(1, 600_000, 300_000)),
                ("yield_time_ms".to_owned(), integer(0, 30_000, 10_000)),
            ]));
            let mut schema = object(properties, &[]);
            // oneOf requires exactly one form, including when both are supplied.
            schema["oneOf"] = json!([{"required":["cmd"]},{"required":["argv"]}]);
            schema["properties"]["argv"]["items"] = text();
            schema["properties"]["argv"]["prefixItems"] = json!([nonempty()]);
            schema
        }
        T::WriteStdin => object(
            output_options(Map::from_iter([
                ("command_id".to_owned(), nonempty()),
                ("chars".to_owned(), json!({"type":"string","default":""})),
                ("yield_time_ms".to_owned(), integer(0, 30_000, 10_000)),
            ])),
            &["command_id"],
        ),
        T::KillCommand => object(
            output_options(Map::from_iter([
                ("command_id".to_owned(), nonempty()),
                (
                    "signal".to_owned(),
                    json!({"type":"string","enum":["TERM","KILL","INT"],"default":"TERM"}),
                ),
                ("wait_ms".to_owned(), integer(0, 30_000, 5000)),
                ("kill_wait_ms".to_owned(), integer(0, 30_000, 2000)),
            ])),
            &["command_id"],
        ),
        T::ReadOutput => object(
            json!({
                "output_ref":nonempty(),"stream":choice(&["stdout","stderr"]),
                "offset":{"type":"integer","minimum":0,"default":0},"limit":integer(1,1_048_576,4096)
            }),
            &["output_ref"],
        ),
        T::GitStatus => object(
            json!({
                "repo_path":nonempty(),
                "path":{"type":"string","default":"."},"include_untracked":boolean(true),
                "max_entries":integer(1,10_000,1000)
            }),
            &[],
        ),
        T::GitDiff => object(
            json!({
                "repo_path":nonempty(),
                "path":text(),"paths":strings(),"staged":boolean(false),"unstaged":boolean(true),"include_untracked":boolean(true),
                "context_lines":integer(0,20,3),"max_bytes":integer(1,1_048_576,262_144)
            }),
            &[],
        ),
        T::GitLog => object(
            json!({
                "repo_path":nonempty(),
                "path":{"type":"string","default":"."},"ref":{"type":"string","default":"HEAD"},
                "max_count":integer(1,100,20),"skip":integer(0,10_000,0)
            }),
            &[],
        ),
        T::GitShow => object(
            json!({
                "repo_path":nonempty(),
                "rev":{"type":"string","default":"HEAD"},"path":text(),"paths":strings(),
                "include_diff":boolean(true),"context_lines":integer(0,20,3),"max_bytes":integer(1,1_048_576,262_144)
            }),
            &[],
        ),
        T::GitBlame => object(
            json!({
                "repo_path":nonempty(),
                "path":nonempty(),"rev":text(),"start_line":{"type":"integer","minimum":1,"default":1},
                "end_line":{"type":"integer","minimum":1},"max_lines":integer(1,1000,200)
            }),
            &["path"],
        ),
        T::RequestPermissions => object(
            json!({
                "tool_name":choice(&["exec_command","apply_patch"]),
                "permission":choice(&["network","destructive_command","long_timeout","sensitive_env","shell_expansion","inline_script","privileged_executable","write_generated_or_ignored"]),
                "reason":nonempty(),"arguments":{"type":"object","additionalProperties":true},
                "scope":{"type":"string","enum":["once","session"],"default":"once"},
                "ttl_seconds":integer(1,3600,300)
            }),
            &["tool_name", "permission", "reason", "arguments"],
        ),
        T::ViewImage => object(
            json!({
                "path":nonempty(),"auto_resize":boolean(true),"max_bytes":integer(1024,10_485_760,5_242_880),
                "max_width":integer(1,10_000,2000),"max_height":integer(1,10_000,2000)
            }),
            &["path"],
        ),
        T::RethlasStart => workflow_schema::start(),
        T::RethlasStep => workflow_schema::step(),
        T::RethlasInspect => workflow_schema::inspect(),
        T::RethlasRetrieve => workflow_schema::retrieve(),
        T::RethlasControl => workflow_schema::control(),
        T::RethlasArtifact => workflow_schema::artifact(),
    }
}
