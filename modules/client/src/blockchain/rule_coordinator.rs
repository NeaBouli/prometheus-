//! Bounded development-only orchestration for durable RuleStorage sync (GH-209).
//!
//! The coordinator performs one immediate attempt and then waits a fixed,
//! validated delay after each completed attempt. Attempts are strictly
//! sequential, cancellation drops the in-flight future, and no work is spawned
//! or detached. The existing GH-207 durable sync remains the only component
//! allowed to validate, persist, or install a snapshot.
//!
//! This is an explicit opt-in development/Testnet-10 boundary. It establishes
//! no canonical manifest authority, independent RPC truth/history/finality,
//! IPFS availability or replication, production YARA quality, wallet or chain
//! action, deployment, Mainnet support, or production readiness.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::{sleep, timeout};

use crate::runtime::{require_stub_allowed, require_stub_allowed_for, RuntimeMode};
use crate::security::scanner::YaraScanner;

use super::rule_checkpoint::{sync_rule_snapshot_durable_for_mode, RuleCheckpointStore};
use super::rule_fetch::RuleContentSource;
use super::rule_observation::RuleObservationSource;
use super::rule_sync::RuleSyncEntry;

/// Smallest accepted successful-sync interval.
pub const MIN_SUCCESS_INTERVAL: Duration = Duration::from_secs(1);
/// Largest accepted successful-sync interval.
pub const MAX_SUCCESS_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Smallest accepted failure retry delay.
pub const MIN_FAILURE_BACKOFF: Duration = Duration::from_millis(100);
/// Largest accepted failure retry delay.
pub const MAX_FAILURE_BACKOFF: Duration = Duration::from_secs(60 * 60);
/// Smallest accepted complete-attempt timeout.
pub const MIN_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(100);
/// Largest accepted complete-attempt timeout.
pub const MAX_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(60);

const COMPONENT: &str = "RuleStorage sync coordinator";

/// Generic redacted coordinator failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleCoordinatorError;

impl fmt::Display for RuleCoordinatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuleStorage sync coordinator failed")
    }
}

impl std::error::Error for RuleCoordinatorError {}

/// Validated deterministic coordinator timing policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleCoordinatorConfig {
    success_interval: Duration,
    initial_failure_backoff: Duration,
    max_failure_backoff: Duration,
    attempt_timeout: Duration,
}

impl RuleCoordinatorConfig {
    pub fn new(
        success_interval: Duration,
        initial_failure_backoff: Duration,
        max_failure_backoff: Duration,
        attempt_timeout: Duration,
    ) -> Result<Self, RuleCoordinatorError> {
        if !(MIN_SUCCESS_INTERVAL..=MAX_SUCCESS_INTERVAL).contains(&success_interval)
            || !(MIN_FAILURE_BACKOFF..=MAX_FAILURE_BACKOFF).contains(&initial_failure_backoff)
            || !(MIN_FAILURE_BACKOFF..=MAX_FAILURE_BACKOFF).contains(&max_failure_backoff)
            || !(MIN_ATTEMPT_TIMEOUT..=MAX_ATTEMPT_TIMEOUT).contains(&attempt_timeout)
            || initial_failure_backoff > max_failure_backoff
        {
            return Err(RuleCoordinatorError);
        }
        Ok(Self {
            success_interval,
            initial_failure_backoff,
            max_failure_backoff,
            attempt_timeout,
        })
    }
}

/// One complete owner-pinned snapshot request supplied by the embedding caller.
pub struct RuleSnapshotRequest {
    pub entries: Vec<RuleSyncEntry>,
    pub empty_snapshot_order: Option<u64>,
}

impl fmt::Debug for RuleSnapshotRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleSnapshotRequest")
            .finish_non_exhaustive()
    }
}

pub type RuleSnapshotFuture<'a> =
    Pin<Box<dyn Future<Output = Result<RuleSnapshotRequest, RuleCoordinatorError>> + Send + 'a>>;

/// Caller-trusted source of one complete owner-pinned snapshot request.
pub trait RuleSnapshotProvider: Send + Sync {
    fn fetch_snapshot<'a>(&'a self) -> RuleSnapshotFuture<'a>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleCoordinatorPhase {
    Idle,
    Attempting,
    Sleeping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleCoordinatorOutcome {
    Succeeded,
    Failed,
    TimedOut,
    Cancelled,
}

/// Bounded non-sensitive lifecycle counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleCoordinatorStatus {
    pub attempts: u64,
    pub successes: u64,
    pub failures: u64,
    pub consecutive_failures: u64,
    pub phase: RuleCoordinatorPhase,
    pub last_outcome: Option<RuleCoordinatorOutcome>,
}

impl Default for RuleCoordinatorStatus {
    fn default() -> Self {
        Self {
            attempts: 0,
            successes: 0,
            failures: 0,
            consecutive_failures: 0,
            phase: RuleCoordinatorPhase::Idle,
            last_outcome: None,
        }
    }
}

/// Clonable read-only status view. No input identity is retained.
#[derive(Clone)]
pub struct RuleCoordinatorStatusHandle {
    inner: Arc<Mutex<RuleCoordinatorStatus>>,
}

impl fmt::Debug for RuleCoordinatorStatusHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleCoordinatorStatusHandle")
            .finish_non_exhaustive()
    }
}

impl RuleCoordinatorStatusHandle {
    pub fn snapshot(&self) -> RuleCoordinatorStatus {
        match self.inner.lock() {
            Ok(status) => *status,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }
}

/// Single-flight lifecycle owner for the existing durable sync transaction.
pub struct RuleCoordinator {
    mode: RuntimeMode,
    config: RuleCoordinatorConfig,
    running: AtomicBool,
    status: Arc<Mutex<RuleCoordinatorStatus>>,
}

impl RuleCoordinator {
    pub fn new(config: RuleCoordinatorConfig) -> Result<Self, RuleCoordinatorError> {
        require_stub_allowed(COMPONENT).map_err(|_| RuleCoordinatorError)?;
        Ok(Self::build(RuntimeMode::from_env(), config))
    }

    pub fn new_for_mode(
        mode: RuntimeMode,
        config: RuleCoordinatorConfig,
    ) -> Result<Self, RuleCoordinatorError> {
        require_stub_allowed(COMPONENT).map_err(|_| RuleCoordinatorError)?;
        require_stub_allowed_for(mode, COMPONENT).map_err(|_| RuleCoordinatorError)?;
        Ok(Self::build(mode, config))
    }

    fn build(mode: RuntimeMode, config: RuleCoordinatorConfig) -> Self {
        Self {
            mode,
            config,
            running: AtomicBool::new(false),
            status: Arc::new(Mutex::new(RuleCoordinatorStatus::default())),
        }
    }

    pub fn status(&self) -> RuleCoordinatorStatus {
        self.status_handle().snapshot()
    }

    pub fn status_handle(&self) -> RuleCoordinatorStatusHandle {
        RuleCoordinatorStatusHandle {
            inner: Arc::clone(&self.status),
        }
    }

    /// Run until the boolean shutdown receiver becomes true or its sender closes.
    ///
    /// A shutdown that wins the biased selection drops the attempt future before
    /// this method returns. No background task survives the returned future.
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        &self,
        shutdown: &mut watch::Receiver<bool>,
        store: &dyn RuleCheckpointStore,
        scanner: &mut YaraScanner,
        content_source: &dyn RuleContentSource,
        observation_source: &dyn RuleObservationSource,
        provider: &dyn RuleSnapshotProvider,
    ) -> Result<(), RuleCoordinatorError> {
        require_stub_allowed(COMPONENT).map_err(|_| RuleCoordinatorError)?;
        require_stub_allowed_for(self.mode, COMPONENT).map_err(|_| RuleCoordinatorError)?;
        if self.running.swap(true, Ordering::AcqRel) {
            return Err(RuleCoordinatorError);
        }
        let _guard = RunGuard {
            running: &self.running,
            status: Arc::clone(&self.status),
        };

        let mut delay = Duration::ZERO;
        let mut failure_backoff = self.config.initial_failure_backoff;
        loop {
            if delay != Duration::ZERO {
                self.update_status(|status| status.phase = RuleCoordinatorPhase::Sleeping);
                tokio::select! {
                    biased;
                    _ = wait_for_shutdown(shutdown) => return Ok(()),
                    _ = sleep(delay) => {}
                }
            }
            if *shutdown.borrow() {
                return Ok(());
            }

            self.update_status(|status| {
                status.phase = RuleCoordinatorPhase::Attempting;
                status.attempts = status.attempts.saturating_add(1);
            });
            let attempt = async {
                let request = provider.fetch_snapshot().await?;
                sync_rule_snapshot_durable_for_mode(
                    self.mode,
                    store,
                    scanner,
                    content_source,
                    observation_source,
                    &request.entries,
                    request.empty_snapshot_order,
                )
                .await
                .map_err(|_| RuleCoordinatorError)
            };
            let result = tokio::select! {
                biased;
                _ = wait_for_shutdown(shutdown) => return Ok(()),
                result = timeout(self.config.attempt_timeout, attempt) => result,
            };

            match result {
                Ok(Ok(())) => {
                    self.update_status(|status| {
                        status.successes = status.successes.saturating_add(1);
                        status.consecutive_failures = 0;
                        status.last_outcome = Some(RuleCoordinatorOutcome::Succeeded);
                    });
                    failure_backoff = self.config.initial_failure_backoff;
                    delay = self.config.success_interval;
                }
                Ok(Err(_)) => {
                    self.record_failure(RuleCoordinatorOutcome::Failed);
                    delay = failure_backoff;
                    failure_backoff =
                        doubled_backoff(failure_backoff, self.config.max_failure_backoff);
                }
                Err(_) => {
                    self.record_failure(RuleCoordinatorOutcome::TimedOut);
                    delay = failure_backoff;
                    failure_backoff =
                        doubled_backoff(failure_backoff, self.config.max_failure_backoff);
                }
            }
        }
    }

    fn record_failure(&self, outcome: RuleCoordinatorOutcome) {
        self.update_status(|status| {
            status.failures = status.failures.saturating_add(1);
            status.consecutive_failures = status.consecutive_failures.saturating_add(1);
            status.last_outcome = Some(outcome);
        });
    }

    fn update_status(&self, update: impl FnOnce(&mut RuleCoordinatorStatus)) {
        match self.status.lock() {
            Ok(mut status) => update(&mut status),
            Err(poisoned) => update(&mut poisoned.into_inner()),
        }
    }
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

fn doubled_backoff(current: Duration, maximum: Duration) -> Duration {
    match current.checked_mul(2) {
        Some(doubled) => doubled.min(maximum),
        None => maximum,
    }
}

struct RunGuard<'a> {
    running: &'a AtomicBool,
    status: Arc<Mutex<RuleCoordinatorStatus>>,
}

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        match self.status.lock() {
            Ok(mut status) => {
                status.phase = RuleCoordinatorPhase::Idle;
                status.last_outcome = Some(RuleCoordinatorOutcome::Cancelled);
            }
            Err(poisoned) => {
                let mut status = poisoned.into_inner();
                status.phase = RuleCoordinatorPhase::Idle;
                status.last_outcome = Some(RuleCoordinatorOutcome::Cancelled);
            }
        }
    }
}
