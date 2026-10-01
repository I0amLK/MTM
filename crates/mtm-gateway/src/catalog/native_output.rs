//! Tool-specific result fields. Unknown extension fields remain allowed; errors
//! retain the common envelope and workflow results keep their own contracts.
use super::*;
pub(super) fn properties(id: ToolId) -> Map<String, Value> {
    use ToolId as T;
    let array = || json!({"type":"array"});
    let number = || json!({"type":"integer"});
    let nullable_number = || json!({"type":["integer","null"]});
    let bool_schema = || json!({"type":"boolean"});
    let object_schema = || json!({"type":"object"});
    let value = match id {
        T::ServerInfo => json!({"server":text(),"version":text(),"workspace":text(),
            "tool_count":number(),"tools":array(),"tool_contract_version":text(),"output_retention":object_schema(),
            "native_tool_count":number(),"rethlas_tool_count":number(),"workspace_mutation_policy":object_schema()}),
        T::CheckExecEnvironment => json!({"native_mode":text(),"permission_mode":text(),
            "native_exec_backend":text(),"private_vault_visible":bool_schema(),"network_allowed":bool_schema(),"warnings":array()}),
        T::ReadFile => {
            json!({"path":text(),"content":text(),"revision":text(),"revision_algorithm":json!({"type":"string","enum":["sha256"]}),
            "sha256":text(),"start_line":number(),"end_line":number(),"total_lines":number(),"total_bytes":number(),
            "line_byte_offset":number(),"truncated":bool_schema(),"next_start_line":nullable_number(),
            "next_line_byte_offset":nullable_number(),"next_action":json!({"type":["object","null"]})})
        }
        T::ListDir => json!({"path":text(),"entries":array(),"truncated":bool_schema()}),
        T::ListFiles => json!({"path":text(),"files":array(),"truncated":bool_schema()}),
        T::SearchText => {
            json!({"matches":array(),"total_matches":number(),"truncated":bool_schema()})
        }
        T::ApplyPatch | T::ApplyChanges => json!({"clean":bool_schema(),"dry_run":bool_schema(),
            "already_applied":bool_schema(),"idempotent_replay":bool_schema(),"summary":text(),"affected_files":array(),
            "additions":number(),"removals":number(),"revision_algorithm":json!({"type":"string","enum":["sha256"]}),"warnings":array()}),
        T::ExecCommand | T::WriteStdin | T::KillCommand => {
            json!({"command_id":text(),"status":text(),
            "exit_code":nullable_number(),"signal":json!({"type":["string","null"]}),"timed_out":bool_schema(),
            "operation_outcome":json!({"type":"string","enum":["running","exited_0","exited_nonzero","timeout","signal","spawn_error"]}),
            "stdout":text(),"stderr":text(),"output_refs":object_schema(),"summary":text(),"warnings":array()})
        }
        T::ReadOutput => {
            json!({"command_id":text(),"output_ref":text(),"stream":text(),"content":text(),
            "offset":number(),"next_offset":nullable_number(),"head_retained_bytes":number(),"evicted_gap_bytes":number(),
            "operation_outcome":text(),"total_stream_bytes":number()})
        }
        T::GitStatus => {
            json!({"is_repo":bool_schema(),"repo_path":text(),"branch":json!({"type":["string","null"]}),
            "head":text(),"entries":array(),"clean":bool_schema(),"truncated":bool_schema()})
        }
        T::GitDiff => {
            json!({"repo_path":text(),"diff":text(),"files":array(),"truncated":bool_schema(),"warnings":array()})
        }
        T::GitLog => {
            json!({"is_repo":bool_schema(),"repo_path":text(),"commits":array(),"truncated":bool_schema()})
        }
        T::GitShow => {
            json!({"is_repo":bool_schema(),"repo_path":text(),"content":text(),"files":array(),"truncated":bool_schema()})
        }
        T::GitBlame => {
            json!({"repo_path":text(),"path":text(),"lines":array(),"truncated":bool_schema(),
            "next_action":json!({"type":["object","null"]})})
        }
        T::RequestPermissions => {
            json!({"status":text(),"grant_id":text(),"constraints":object_schema(),
            "expires_at":json!({"type":["string","integer","null"]}),"warnings":array()})
        }
        T::ViewImage => {
            json!({"path":text(),"mime_type":text(),"bytes":number(),"width":nullable_number(),
            "height":nullable_number(),"resized":bool_schema(),"original":object_schema(),"warnings":array()})
        }
        _ => json!({}),
    };
    value.as_object().cloned().unwrap_or_default()
}
