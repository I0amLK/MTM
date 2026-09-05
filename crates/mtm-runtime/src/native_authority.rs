#![expect(
    dead_code,
    reason = "MTM-014 D5 cutover candidate must remain unreachable until real human MRTR evidence is accepted"
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use mtm_contracts::{ErrorCategory, NativePermissionKind, NativePermissionTool, ReCtmError};
use mtm_core::{
    EffectiveNativePolicy, NativeInvocation, PatchInvocation, classify_patch_permissions,
};
use serde_json::{Map, Value};

use crate::{NativePermissionGrantAuthority, NativeToolRuntime, NativeWorkspace};

/// Pre-cutover execution seam for MTM-014 D5.
///
/// This type is intentionally crate-private and is not reachable from MCP
/// dispatch. It exists so the complete grant -> SandboxPlan/PreparedPatch ->
/// execution path can be qualified before the independent human-consent gate
/// authorizes the final public cutover.
pub(crate) struct NativeAuthorityExecutor {
    native: Arc<NativeToolRuntime>,
    workspace: Arc<NativeWorkspace>,
    grants: Arc<NativePermissionGrantAuthority>,
}

impl NativeAuthorityExecutor {
    pub(crate) fn new(
        native: Arc<NativeToolRuntime>,
        workspace: Arc<NativeWorkspace>,
        grants: Arc<NativePermissionGrantAuthority>,
    ) -> Self {
        Self {
            native,
            workspace,
            grants,
        }
    }

    pub(crate) fn exec_command_candidate(
        &self,
        owner_id: &str,
        arguments: &Map<String, Value>,
    ) -> Result<Value, ReCtmError> {
        let prepared = self.native.prepare_authority_exec(arguments)?;
        let revalidated = self.native.revalidate_authority_exec(prepared)?;
        let permit = self.grants.authorize_invocation(
            owner_id,
            &self.workspace.root().display().to_string(),
            revalidated.policy(),
        )?;
        self.native.start_authority_exec(revalidated, permit)
    }

    pub(crate) fn apply_patch_candidate(
        &self,
        owner_id: &str,
        arguments: &Map<String, Value>,
    ) -> Result<Value, ReCtmError> {
        let invocation = PatchInvocation::parse(arguments)?;
        let prepared = self.workspace.prepare_patch(&invocation)?;
        let path_facts = prepared
            .path_facts()
            .ok_or_else(|| internal("authority patch preparation omitted path facts"))?;
        let required = classify_patch_permissions(&invocation, path_facts)?;
        let native_invocation = NativeInvocation::Patch(invocation.clone());
        let policy = EffectiveNativePolicy::evaluate(
            self.native.mode(),
            &native_invocation,
            &required,
            &BTreeSet::new(),
        )?;
        let workspace = self.workspace.root().display().to_string();
        let expected_explicit = policy
            .required()
            .iter()
            .copied()
            .filter(|kind| !policy.implicitly_granted().contains(kind))
            .collect::<Vec<_>>();
        let expected_digest = invocation.arguments_sha256().to_owned();
        self.workspace
            .commit_prepared_patch_with_authorization(prepared, || {
                let permit = self
                    .grants
                    .authorize_invocation(owner_id, &workspace, &policy)?;
                validate_permit(
                    &permit,
                    NativePermissionTool::ApplyPatch,
                    &expected_digest,
                    &expected_explicit,
                )
            })
    }
}

fn validate_permit(
    permit: &crate::NativeInvocationPermissionPermit,
    tool: NativePermissionTool,
    arguments_sha256: &str,
    expected_permissions: &[NativePermissionKind],
) -> Result<(), ReCtmError> {
    if permit.tool() != tool
        || permit.arguments_sha256() != arguments_sha256
        || permit.permissions() != expected_permissions
    {
        return Err(ReCtmError::new(
            "NATIVE_PERMISSION_PERMIT_MISMATCH",
            "Native invocation permit does not match the authorized operation.",
        )
        .with_category(ErrorCategory::Security));
    }
    Ok(())
}

fn internal(message: &str) -> ReCtmError {
    ReCtmError::new("NATIVE_PERMISSION_INTERNAL_ERROR", message)
        .with_category(ErrorCategory::Internal)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use mtm_contracts::{NativeMode, NativePermissionScope};
    use mtm_core::NativePermissionRequest;
    use mtm_storage::StoreRuntime;

    use crate::{NativePermissionConsentAuthority, NativePermissionConsentOutcome};

    use super::*;

    fn patch_arguments(path: &str, content: &str, dry_run: bool) -> Map<String, Value> {
        serde_json::json!({
            "patch":format!(
                "*** Begin Patch\n*** Add File: {path}\n+{content}\n*** End Patch\n"
            ),
            "dry_run":dry_run
        })
        .as_object()
        .cloned()
        .unwrap_or_default()
    }

    fn issue_patch_grant(
        grants: &NativePermissionGrantAuthority,
        consents: &NativePermissionConsentAuthority,
        owner: &str,
        workspace: &str,
        arguments: &Map<String, Value>,
    ) -> Result<(), ReCtmError> {
        let request = NativePermissionRequest::parse(
            serde_json::json!({
                "tool_name":"apply_patch",
                "permission":"write_generated_or_ignored",
                "reason":"candidate patch test",
                "arguments":arguments,
                "scope":NativePermissionScope::Once.as_str(),
                "ttl_seconds":300
            })
            .as_object()
            .ok_or_else(|| internal("test permission request must be an object"))?,
        )?;
        let prompt = consents.begin(owner, workspace, request.clone())?;
        let outcome = consents.complete(
            prompt.request_state(),
            owner,
            workspace,
            &request,
            &serde_json::json!({"action":"accept","content":{"approved":true}}),
        )?;
        let NativePermissionConsentOutcome::Accepted(consent) = outcome else {
            return Err(internal("test consent was not accepted"));
        };
        grants.issue_verified(consent)?;
        Ok(())
    }

    struct CandidateFixture {
        _root: tempfile::TempDir,
        workspace: Arc<NativeWorkspace>,
        grants: Arc<NativePermissionGrantAuthority>,
        consents: NativePermissionConsentAuthority,
        executor: NativeAuthorityExecutor,
    }

    fn candidate_fixture() -> Result<CandidateFixture, ReCtmError> {
        let root = tempfile::tempdir().map_err(|error| internal(&error.to_string()))?;
        let private = root.path().join("private-outside-workspace");
        let workspace_root = root.path().join("workspace");
        fs::create_dir_all(&private).map_err(|error| internal(&error.to_string()))?;
        fs::create_dir_all(&workspace_root).map_err(|error| internal(&error.to_string()))?;
        let workspace = Arc::new(NativeWorkspace::new(&workspace_root, &private)?);
        let native = Arc::new(NativeToolRuntime::new(
            Arc::clone(&workspace),
            NativeMode::Safe,
            "disabled",
            &[],
            std::slice::from_ref(&private),
        )?);
        let runtime = StoreRuntime::default();
        let grants = Arc::new(NativePermissionGrantAuthority::new(runtime.clone()));
        let consents = NativePermissionConsentAuthority::new(runtime);
        let executor =
            NativeAuthorityExecutor::new(native, Arc::clone(&workspace), Arc::clone(&grants));
        Ok(CandidateFixture {
            _root: root,
            workspace,
            grants,
            consents,
            executor,
        })
    }

    #[test]
    fn generated_patch_requires_exact_once_grant_and_consumes_it() -> Result<(), ReCtmError> {
        let fixture = candidate_fixture()?;
        fs::create_dir_all(fixture.workspace.root().join("build"))
            .map_err(|error| internal(&error.to_string()))?;
        let owner = "owner-a";
        let workspace_text = fixture.workspace.root().display().to_string();
        let arguments = patch_arguments("build/generated.txt", "approved", false);

        let denied = fixture.executor.apply_patch_candidate(owner, &arguments);
        assert_eq!(
            denied.map_err(|error| error.code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        assert!(
            !fixture
                .workspace
                .root()
                .join("build/generated.txt")
                .exists()
        );

        issue_patch_grant(
            &fixture.grants,
            &fixture.consents,
            owner,
            &workspace_text,
            &arguments,
        )?;
        let result = fixture.executor.apply_patch_candidate(owner, &arguments)?;
        assert_eq!(result["dry_run"], false);
        assert_eq!(
            fs::read_to_string(fixture.workspace.root().join("build/generated.txt"))
                .map_err(|error| internal(&error.to_string()))?,
            "approved\n"
        );
        assert_eq!(
            fixture
                .grants
                .authorize_matching_grants(
                    owner,
                    &workspace_text,
                    NativePermissionTool::ApplyPatch,
                    &[NativePermissionKind::WriteGeneratedOrIgnored],
                    &arguments,
                )
                .map_err(|error| error.code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        Ok(())
    }

    #[test]
    fn dry_run_and_normal_patch_need_no_explicit_grant() -> Result<(), ReCtmError> {
        let fixture = candidate_fixture()?;
        fs::create_dir_all(fixture.workspace.root().join("build"))
            .map_err(|error| internal(&error.to_string()))?;

        let dry = patch_arguments("build/dry.txt", "dry", true);
        let dry_result = fixture.executor.apply_patch_candidate("owner-a", &dry)?;
        assert_eq!(dry_result["dry_run"], true);
        assert!(!fixture.workspace.root().join("build/dry.txt").exists());

        let normal = patch_arguments("normal.txt", "normal", false);
        let result = fixture.executor.apply_patch_candidate("owner-a", &normal)?;
        assert_eq!(result["dry_run"], false);
        assert_eq!(
            fs::read_to_string(fixture.workspace.root().join("normal.txt"))
                .map_err(|error| internal(&error.to_string()))?,
            "normal\n"
        );
        Ok(())
    }

    #[test]
    fn patch_argument_mutation_cannot_reuse_grant() -> Result<(), ReCtmError> {
        let fixture = candidate_fixture()?;
        fs::create_dir_all(fixture.workspace.root().join("build"))
            .map_err(|error| internal(&error.to_string()))?;
        let owner = "owner-a";
        let workspace_text = fixture.workspace.root().display().to_string();
        let original = patch_arguments("build/original.txt", "one", false);
        let mutated = patch_arguments("build/mutated.txt", "two", false);
        issue_patch_grant(
            &fixture.grants,
            &fixture.consents,
            owner,
            &workspace_text,
            &original,
        )?;

        assert_eq!(
            fixture
                .executor
                .apply_patch_candidate(owner, &mutated)
                .map_err(|error| error.code),
            Err("NATIVE_PERMISSION_GRANT_SET_INCOMPLETE".to_owned())
        );
        assert!(!fixture.workspace.root().join("build/original.txt").exists());
        assert!(!fixture.workspace.root().join("build/mutated.txt").exists());

        fixture.executor.apply_patch_candidate(owner, &original)?;
        assert!(
            fixture
                .workspace
                .root()
                .join("build/original.txt")
                .is_file()
        );
        Ok(())
    }
}
