use mtm_contracts::{ErrorCategory, ReCtmError};
use serde_json::Value;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResearchRequest {
    pub operation: String,
    pub query: String,
    pub author: String,
    pub title: String,
    pub keywords: String,
    pub search_intent: String,
    pub num_results: usize,
}

pub trait ResearchProvider: Send + Sync {
    fn retrieve(&self, request: &ResearchRequest) -> Result<Value, ReCtmError>;
}

#[derive(Default)]
pub struct DisabledResearchProvider;

impl ResearchProvider for DisabledResearchProvider {
    fn retrieve(&self, _request: &ResearchRequest) -> Result<Value, ReCtmError> {
        Err(ReCtmError::new(
            "RESEARCH_PROVIDER_UNAVAILABLE",
            "No external research provider is configured.",
        )
        .with_category(ErrorCategory::Runtime))
    }
}
