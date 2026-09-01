use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mtm_contracts::{ErrorCategory, ReCtmError};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub trait GatewayClock: Send + Sync {
    fn now_unix(&self) -> i64;
    fn now_iso(&self) -> Result<String, ReCtmError>;
}

pub trait IdSource: Send + Sync {
    fn token_urlsafe(&self, bytes: usize) -> Result<String, ReCtmError>;
}

pub type EventSink = Arc<dyn Fn(Value) + Send + Sync + 'static>;

#[derive(Clone)]
pub struct GatewayRuntime {
    pub clock: Arc<dyn GatewayClock>,
    pub ids: Arc<dyn IdSource>,
    pub events: EventSink,
}

impl Default for GatewayRuntime {
    fn default() -> Self {
        Self {
            clock: Arc::new(SystemClock),
            ids: Arc::new(SystemIdSource),
            events: Arc::new(|_| {}),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl GatewayClock for SystemClock {
    fn now_unix(&self) -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }

    fn now_iso(&self) -> Result<String, ReCtmError> {
        OffsetDateTime::now_utc().format(&Rfc3339).map_err(|error| {
            ReCtmError::new("TIME_FORMAT_ERROR", error.to_string())
                .with_category(ErrorCategory::Internal)
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemIdSource;

impl IdSource for SystemIdSource {
    fn token_urlsafe(&self, bytes: usize) -> Result<String, ReCtmError> {
        let mut buffer = vec![0_u8; bytes];
        getrandom::fill(&mut buffer).map_err(|error| {
            ReCtmError::new("RANDOM_SOURCE_ERROR", error.to_string())
                .with_category(ErrorCategory::Internal)
        })?;
        Ok(URL_SAFE_NO_PAD.encode(buffer))
    }
}

#[derive(Clone, Debug)]
pub struct FixedClock {
    unix: i64,
    iso: String,
}

impl FixedClock {
    #[must_use]
    pub fn new(unix: i64, iso: impl Into<String>) -> Self {
        Self {
            unix,
            iso: iso.into(),
        }
    }
}

impl GatewayClock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.unix
    }

    fn now_iso(&self) -> Result<String, ReCtmError> {
        Ok(self.iso.clone())
    }
}

#[derive(Clone, Debug)]
pub struct SequenceIdSource {
    values: Arc<Mutex<VecDeque<String>>>,
}

impl SequenceIdSource {
    #[must_use]
    pub fn new(values: impl IntoIterator<Item = String>) -> Self {
        Self {
            values: Arc::new(Mutex::new(values.into_iter().collect())),
        }
    }
}

impl IdSource for SequenceIdSource {
    fn token_urlsafe(&self, _bytes: usize) -> Result<String, ReCtmError> {
        self.values
            .lock()
            .map_err(|_| {
                ReCtmError::new("ID_SOURCE_LOCK_ERROR", "ID source lock was poisoned.")
                    .with_category(ErrorCategory::Internal)
            })?
            .pop_front()
            .ok_or_else(|| {
                ReCtmError::new(
                    "ID_SOURCE_EXHAUSTED",
                    "Deterministic ID source is exhausted.",
                )
                .with_category(ErrorCategory::Internal)
            })
    }
}
