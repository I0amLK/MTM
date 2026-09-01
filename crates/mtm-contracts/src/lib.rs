#![forbid(unsafe_code)]

/// Number of public CTM-compatible native tools in the source contract.
pub const NATIVE_TOOL_COUNT: u16 = 18;

/// Number of public Rethlas façade tools in the source contract.
pub const RETHLAS_TOOL_COUNT: u16 = 6;

/// Number of hidden compatibility aliases in the source contract.
pub const HIDDEN_ALIAS_COUNT: u16 = 11;

/// Current persistent-state schema supported by the source baseline.
pub const STATE_SCHEMA_VERSION: u16 = 2;

/// Current workflow protocol supported by the source baseline.
pub const WORKFLOW_PROTOCOL_VERSION: u16 = 2;

/// Total public tools exposed by the source contract.
pub const PUBLIC_TOOL_COUNT: u16 = NATIVE_TOOL_COUNT + RETHLAS_TOOL_COUNT;

/// Which implementation is allowed to perform production side effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeAuthority {
    /// Re-CTM's Python runtime remains authoritative.
    Python,
    /// Rust executes only read-only differential shadow checks.
    RustShadow,
    /// Rust owns the production behavior for the component.
    Rust,
    /// The component is retired and has no production authority.
    Retired,
}

impl RuntimeAuthority {
    /// Return the stable wire label used in records and reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::RustShadow => "rust-shadow",
            Self::Rust => "rust",
            Self::Retired => "retired",
        }
    }
}

/// Stable source-contract snapshot used by the first conformance gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContractSnapshot {
    /// Native public tool count.
    pub native_tools: u16,
    /// Rethlas public tool count.
    pub rethlas_tools: u16,
    /// Hidden legacy alias count.
    pub hidden_aliases: u16,
    /// Persistent-state schema version.
    pub state_schema: u16,
    /// Workflow protocol version.
    pub workflow_protocol: u16,
    /// Current production authority.
    pub authority: RuntimeAuthority,
}

impl ContractSnapshot {
    /// Return the immutable bootstrap source contract.
    #[must_use]
    pub const fn source_baseline() -> Self {
        Self {
            native_tools: NATIVE_TOOL_COUNT,
            rethlas_tools: RETHLAS_TOOL_COUNT,
            hidden_aliases: HIDDEN_ALIAS_COUNT,
            state_schema: STATE_SCHEMA_VERSION,
            workflow_protocol: WORKFLOW_PROTOCOL_VERSION,
            authority: RuntimeAuthority::Python,
        }
    }

    /// Render the bootstrap contract as deterministic JSON without external dependencies.
    #[must_use]
    pub fn to_json(self) -> String {
        format!(
            concat!(
                "{{\"schema_version\":\"1.0.0\",",
                "\"native_tools\":{},",
                "\"rethlas_tools\":{},",
                "\"public_tools\":{},",
                "\"hidden_aliases\":{},",
                "\"state_schema\":{},",
                "\"workflow_protocol\":{},",
                "\"authority\":\"{}\"}}"
            ),
            self.native_tools,
            self.rethlas_tools,
            self.native_tools + self.rethlas_tools,
            self.hidden_aliases,
            self.state_schema,
            self.workflow_protocol,
            self.authority.as_str(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_contract_is_frozen() {
        let contract = ContractSnapshot::source_baseline();
        assert_eq!(contract.native_tools, 18);
        assert_eq!(contract.rethlas_tools, 6);
        assert_eq!(contract.native_tools + contract.rethlas_tools, 24);
        assert_eq!(contract.hidden_aliases, 11);
        assert_eq!(contract.state_schema, 2);
        assert_eq!(contract.workflow_protocol, 2);
        assert_eq!(contract.authority, RuntimeAuthority::Python);
    }

    #[test]
    fn bootstrap_json_is_deterministic() {
        assert_eq!(
            ContractSnapshot::source_baseline().to_json(),
            "{\"schema_version\":\"1.0.0\",\"native_tools\":18,\"rethlas_tools\":6,\"public_tools\":24,\"hidden_aliases\":11,\"state_schema\":2,\"workflow_protocol\":2,\"authority\":\"python\"}"
        );
    }
}
