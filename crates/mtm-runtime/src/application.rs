use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use mtm_contracts::{ErrorCategory, ReCtmError};
use mtm_gateway::{
    GatewayHttpConfig, GatewayRuntime, GatewayState, MCPDispatcher, OAuthService, OAuthStore,
    ToolBackend, ToolCatalog,
};
use mtm_storage::{CapabilityAuthority, CapabilityEvent, CapabilityObserver, StateStore};
use mtm_workflow::{
    PrivateVault, ResearchProvider, TaskCatalog, WorkflowEngine, WorkflowEvent, WorkflowObserver,
};
use serde_json::Value;

use crate::{
    CurlResearchProvider, NativeToolRuntime, NativeWorkspace, RuntimeEventSink, RuntimeLatexGate,
    RuntimeSettings, RuntimeToolBackend,
};

#[derive(Clone, Debug)]
pub struct RuntimeAssets {
    tool_catalog: Value,
    methodology: Value,
}

impl RuntimeAssets {
    pub fn new(tool_catalog: Value, methodology: Value) -> Result<Self, ReCtmError> {
        ToolCatalog::from_source_snapshot(&tool_catalog)?;
        TaskCatalog::from_source_snapshot(methodology.clone())?;
        Ok(Self {
            tool_catalog,
            methodology,
        })
    }

    pub fn from_json(tool_catalog: &str, methodology: &str) -> Result<Self, ReCtmError> {
        let tool_catalog = serde_json::from_str(tool_catalog).map_err(asset_json_error)?;
        let methodology = serde_json::from_str(methodology).map_err(asset_json_error)?;
        Self::new(tool_catalog, methodology)
    }

    pub fn from_base64_catalog(
        tool_catalog_base64: &str,
        methodology: &str,
    ) -> Result<Self, ReCtmError> {
        let compact = tool_catalog_base64
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        let bytes = STANDARD.decode(compact).map_err(|_| {
            ReCtmError::new(
                "RUNTIME_ASSET_BASE64_INVALID",
                "Embedded tool catalog is not valid base64.",
            )
            .with_category(ErrorCategory::Internal)
        })?;
        let tool_catalog = std::str::from_utf8(&bytes).map_err(|_| {
            ReCtmError::new(
                "RUNTIME_ASSET_UTF8_INVALID",
                "Embedded tool catalog is not valid UTF-8.",
            )
            .with_category(ErrorCategory::Internal)
        })?;
        Self::from_json(tool_catalog, methodology)
    }

    pub fn tool_catalog(&self) -> &Value {
        &self.tool_catalog
    }

    pub fn methodology(&self) -> &Value {
        &self.methodology
    }
}

pub struct RuntimeApplication {
    pub settings: RuntimeSettings,
    pub state_store: Arc<StateStore>,
    pub oauth_store: Arc<OAuthStore>,
    pub vault: Arc<PrivateVault>,
    pub capabilities: Arc<CapabilityAuthority>,
    pub native: Arc<NativeToolRuntime>,
    pub workflow: Arc<WorkflowEngine>,
    pub backend: Arc<RuntimeToolBackend>,
    pub catalog: Arc<ToolCatalog>,
    pub oauth: Arc<OAuthService>,
    pub mcp: Arc<MCPDispatcher>,
    pub gateway: Arc<GatewayState>,
}

impl RuntimeApplication {
    pub fn build(
        settings: RuntimeSettings,
        assets: &RuntimeAssets,
        bind_host: &str,
        bind_port: u16,
        complete_flow_locally_validated: bool,
    ) -> Result<Self, ReCtmError> {
        Self::build_with_observer(
            settings,
            assets,
            bind_host,
            bind_port,
            complete_flow_locally_validated,
            None,
        )
    }

    pub fn build_with_observer(
        settings: RuntimeSettings,
        assets: &RuntimeAssets,
        bind_host: &str,
        bind_port: u16,
        complete_flow_locally_validated: bool,
        observer: Option<RuntimeEventSink>,
    ) -> Result<Self, ReCtmError> {
        settings.validate()?;
        settings.ensure_directories()?;
        if settings.token_secret.len() < 32 || settings.capability_secret.len() < 32 {
            return Err(ReCtmError::new(
                "RUNTIME_SECRETS_REQUIRED",
                "Runtime secrets must be materialized before application construction.",
            )
            .with_category(ErrorCategory::Security));
        }
        if settings.oauth_password.is_empty() {
            return Err(ReCtmError::new(
                "OAUTH_PASSWORD_REQUIRED",
                "OAuth operator password must be configured or generated before application construction.",
            )
            .with_category(ErrorCategory::Security));
        }

        let catalog = Arc::new(ToolCatalog::from_source_snapshot(assets.tool_catalog())?);
        let methodology = Arc::new(TaskCatalog::from_source_snapshot(
            assets.methodology().clone(),
        )?);
        let state_store = Arc::new(StateStore::open(
            settings.private_root.join("state.sqlite3"),
        )?);
        let vault = Arc::new(PrivateVault::new(&settings.private_root)?);
        let capability_observer: Option<CapabilityObserver> = observer.as_ref().map(|sink| {
            let sink = Arc::clone(sink);
            Arc::new(move |event: CapabilityEvent| {
                if let Ok(value) = serde_json::to_value(event) {
                    sink(value);
                }
            }) as CapabilityObserver
        });
        let capabilities = Arc::new(CapabilityAuthority::new(
            &settings.capability_secret,
            Arc::clone(&state_store),
            600,
            capability_observer,
        )?);
        let workspace = Arc::new(NativeWorkspace::new(
            &settings.workspace,
            &settings.private_root,
        )?);
        let native = Arc::new(NativeToolRuntime::new(
            Arc::clone(&workspace),
            settings.native_mode,
            &settings.native_exec_backend,
            &settings.native_exec_allow_roots,
            &[settings.data_root.clone(), settings.private_root.clone()],
        )?);
        let latex = Arc::new(RuntimeLatexGate::new(
            settings.latex_policy,
            Arc::clone(&native),
        ));
        let research: Arc<dyn ResearchProvider> = Arc::new(CurlResearchProvider::new(
            &settings.theorem_search_url,
            settings.theorem_search_timeout_seconds,
        )?);
        let workflow_observer: Option<WorkflowObserver> = observer.as_ref().map(|sink| {
            let sink = Arc::clone(sink);
            Arc::new(move |event: WorkflowEvent| {
                if let Ok(value) = serde_json::to_value(event) {
                    sink(value);
                }
            }) as WorkflowObserver
        });
        let workflow = Arc::new(WorkflowEngine::new_with_research(
            Arc::clone(&state_store),
            Arc::clone(&vault),
            Arc::clone(&capabilities),
            methodology,
            latex,
            research,
            workflow_observer,
        ));
        let backend = Arc::new(RuntimeToolBackend::new_with_observer(
            Arc::clone(&native),
            workspace,
            Arc::clone(&workflow),
            Arc::clone(&state_store),
            Arc::clone(&capabilities),
            observer.clone(),
        ));

        let mut gateway_runtime = GatewayRuntime::default();
        if let Some(sink) = observer {
            gateway_runtime.events = sink;
        }
        let oauth_store = Arc::new(OAuthStore::open(
            &settings.data_root.join("oauth.sqlite3"),
            gateway_runtime.clone(),
        )?);
        let oauth = Arc::new(OAuthService::new(
            &settings.oauth_server_url,
            &settings.oauth_password,
            &settings.token_secret,
            Arc::clone(&oauth_store),
            gateway_runtime.clone(),
            24 * 60 * 60,
        )?);
        let backend_trait: Arc<dyn ToolBackend> = backend.clone();
        let mcp = Arc::new(MCPDispatcher::new(
            Arc::clone(&catalog),
            backend_trait,
            gateway_runtime.clone(),
        ));
        let gateway = Arc::new(GatewayState::new(
            Arc::clone(&oauth),
            Arc::clone(&mcp),
            Arc::clone(&catalog),
            gateway_runtime,
            GatewayHttpConfig {
                bind_host: bind_host.to_owned(),
                bind_port,
                fixed_oauth_origin: settings.oauth_server_url.clone(),
                allowed_origins: settings.allowed_origins.clone(),
                complete_flow_locally_validated,
            },
        )?);

        Ok(Self {
            settings,
            state_store,
            oauth_store,
            vault,
            capabilities,
            native,
            workflow,
            backend,
            catalog,
            oauth,
            mcp,
            gateway,
        })
    }

    pub fn close(&self) -> Result<(), ReCtmError> {
        self.native.close()
    }
}

pub fn attest_native(settings: &RuntimeSettings) -> Result<Value, ReCtmError> {
    settings.validate()?;
    let workspace = Arc::new(NativeWorkspace::new(
        &settings.workspace,
        &settings.private_root,
    )?);
    let native = NativeToolRuntime::new(
        workspace,
        settings.native_mode,
        "bubblewrap",
        &settings.native_exec_allow_roots,
        &[settings.data_root.clone(), settings.private_root.clone()],
    )?;
    let info = native.server_info();
    native.close()?;
    Ok(serde_json::json!({
        "ok":true,
        "backend":"bubblewrap",
        "workspace":settings.workspace,
        "data_root":settings.data_root,
        "private_root":settings.private_root,
        "toolchain_exposure":info["toolchain_exposure"],
        "attestation":info["native_exec_attestation"],
    }))
}

fn asset_json_error(error: serde_json::Error) -> ReCtmError {
    ReCtmError::new("RUNTIME_ASSET_JSON_INVALID", error.to_string())
        .with_category(ErrorCategory::Internal)
}
