//! Deterministic GH-209 coordinator lifecycle tests.
//!
//! Empty snapshots exercise orchestration and GH-207 checkpoint ordering
//! without network, content, manifests, addresses, or chain fixtures.

use std::collections::VecDeque;
use std::future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use kaspa_addresses::Address;
use prometheus_client::blockchain::rule_checkpoint::{
    RuleCheckpointError, RuleCheckpointLock, RuleCheckpointStore,
};
use prometheus_client::blockchain::rule_coordinator::{
    RuleCoordinator, RuleCoordinatorConfig, RuleCoordinatorError, RuleCoordinatorOutcome,
    RuleCoordinatorPhase, RuleCoordinatorStatus, RuleSnapshotFuture, RuleSnapshotProvider,
    RuleSnapshotRequest, MAX_ATTEMPT_TIMEOUT, MAX_FAILURE_BACKOFF, MAX_SUCCESS_INTERVAL,
    MIN_ATTEMPT_TIMEOUT, MIN_FAILURE_BACKOFF, MIN_SUCCESS_INTERVAL,
};
use prometheus_client::blockchain::rule_fetch::{
    RuleContentFuture, RuleContentSource, RuleFetchError,
};
use prometheus_client::blockchain::rule_observation::{
    RuleObservationError, RuleObservationFuture, RuleObservationSource,
};
use prometheus_client::blockchain::rule_sync::RuleSyncEntry;
use prometheus_client::runtime::RuntimeMode;
use prometheus_client::security::scanner::{CompiledRule, YaraScanner};
use tokio::sync::watch;
use tokio::time::{sleep, Instant};

const SUCCESS_INTERVAL: Duration = Duration::from_secs(2);
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_millis(400);
const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Default)]
struct MemoryStore {
    state: Mutex<Option<Vec<u8>>>,
    replacements: AtomicU64,
}

impl MemoryStore {
    fn seed(&self, order: u64, digest: char) {
        let digest = digest.to_string().repeat(64);
        let bytes = format!(
            "{{\"schema_version\":1,\"kind\":\"prometheus.rule-storage.checkpoint.v1\",\"network_id\":\"testnet-10\",\"order\":{order},\"snapshot_digest\":\"{digest}\"}}"
        )
        .into_bytes();
        *self.state.lock().unwrap() = Some(bytes);
    }

    fn bytes(&self) -> Option<Vec<u8>> {
        self.state.lock().unwrap().clone()
    }

    fn replacement_count(&self) -> u64 {
        self.replacements.load(Ordering::SeqCst)
    }
}

struct MemoryLock<'a> {
    store: &'a MemoryStore,
}

impl RuleCheckpointStore for MemoryStore {
    fn lock(&self) -> Result<Box<dyn RuleCheckpointLock + '_>, RuleCheckpointError> {
        Ok(Box::new(MemoryLock { store: self }))
    }
}

impl RuleCheckpointLock for MemoryLock<'_> {
    fn read(&self) -> Result<Option<Vec<u8>>, RuleCheckpointError> {
        Ok(self.store.bytes())
    }

    fn replace(&self, canonical_bytes: &[u8]) -> Result<(), RuleCheckpointError> {
        *self.store.state.lock().unwrap() = Some(canonical_bytes.to_vec());
        self.store.replacements.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct PanicContentSource;

impl RuleContentSource for PanicContentSource {
    fn fetch_rule_content<'a>(&'a self, _canonical_cid: &'a str) -> RuleContentFuture<'a> {
        Box::pin(async { Err(RuleFetchError) })
    }
}

struct PanicObservationSource;

impl RuleObservationSource for PanicObservationSource {
    fn observe_address<'a>(&'a self, _address: &'a Address) -> RuleObservationFuture<'a> {
        Box::pin(async { Err(RuleObservationError) })
    }
}

#[derive(Clone, Copy)]
enum ProviderStep {
    Empty(u64),
    Fail,
    Pending,
}

struct SequenceProvider {
    steps: Mutex<VecDeque<ProviderStep>>,
    calls: Mutex<Vec<Instant>>,
}

impl SequenceProvider {
    fn new(steps: impl IntoIterator<Item = ProviderStep>) -> Self {
        Self {
            steps: Mutex::new(steps.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn empty(order: u64) -> Self {
        Self::new([ProviderStep::Empty(order)])
    }

    fn call_instants(&self) -> Vec<Instant> {
        self.calls.lock().unwrap().clone()
    }

    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl RuleSnapshotProvider for SequenceProvider {
    fn fetch_snapshot<'a>(&'a self) -> RuleSnapshotFuture<'a> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(Instant::now());
            let step = {
                let mut steps = self.steps.lock().unwrap();
                let step = steps.pop_front();
                if let Some(last) = step {
                    if steps.is_empty() {
                        steps.push_back(last);
                    }
                }
                step
            };
            match step {
                Some(ProviderStep::Empty(order)) => Ok(RuleSnapshotRequest {
                    entries: Vec::new(),
                    empty_snapshot_order: Some(order),
                }),
                Some(ProviderStep::Pending) => future::pending().await,
                Some(ProviderStep::Fail) | None => Err(RuleCoordinatorError),
            }
        })
    }
}

fn config() -> RuleCoordinatorConfig {
    RuleCoordinatorConfig::new(
        SUCCESS_INTERVAL,
        INITIAL_BACKOFF,
        MAX_BACKOFF,
        ATTEMPT_TIMEOUT,
    )
    .unwrap()
}

fn scanner_with_old_rule() -> YaraScanner {
    let mut scanner = YaraScanner::new().unwrap();
    scanner
        .add_rule(CompiledRule {
            name: "OLD-RULE".to_string(),
            patterns: vec![b"OLDPATTERN".to_vec()],
            required_matches: 1,
        })
        .unwrap();
    scanner
}

fn old_rule_is_intact(scanner: &YaraScanner) -> bool {
    scanner.rule_count() == 1 && scanner.scan_bytes(b"OLDPATTERN").unwrap().is_threat
}

enum Target {
    Successes(u64),
    Failures(u64),
}

impl Target {
    fn reached(&self, status: RuleCoordinatorStatus) -> bool {
        match self {
            Self::Successes(count) => status.successes >= *count,
            Self::Failures(count) => status.failures >= *count,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_until(
    coordinator: &RuleCoordinator,
    target: Target,
    store: &dyn RuleCheckpointStore,
    scanner: &mut YaraScanner,
    content: &dyn RuleContentSource,
    observation: &dyn RuleObservationSource,
    provider: &dyn RuleSnapshotProvider,
) -> (Result<(), RuleCoordinatorError>, RuleCoordinatorStatus) {
    let handle = coordinator.status_handle();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let driver = async {
        for _ in 0..20_000 {
            let status = handle.snapshot();
            if target.reached(status) {
                let _ = shutdown_tx.send(true);
                return status;
            }
            sleep(Duration::from_millis(10)).await;
        }
        panic!("coordinator target was not reached");
    };
    let run = coordinator.run(
        &mut shutdown_rx,
        store,
        scanner,
        content,
        observation,
        provider,
    );
    tokio::join!(run, driver)
}

#[test]
fn config_mode_and_diagnostics_are_bounded() {
    assert!(RuleCoordinatorConfig::new(
        MIN_SUCCESS_INTERVAL,
        MIN_FAILURE_BACKOFF,
        MIN_FAILURE_BACKOFF,
        MIN_ATTEMPT_TIMEOUT,
    )
    .is_ok());
    assert!(RuleCoordinatorConfig::new(
        MAX_SUCCESS_INTERVAL,
        MAX_FAILURE_BACKOFF,
        MAX_FAILURE_BACKOFF,
        MAX_ATTEMPT_TIMEOUT,
    )
    .is_ok());
    assert!(RuleCoordinatorConfig::new(
        MIN_SUCCESS_INTERVAL - Duration::from_nanos(1),
        MIN_FAILURE_BACKOFF,
        MIN_FAILURE_BACKOFF,
        MIN_ATTEMPT_TIMEOUT,
    )
    .is_err());
    assert!(RuleCoordinatorConfig::new(
        MIN_SUCCESS_INTERVAL,
        MIN_FAILURE_BACKOFF * 2,
        MIN_FAILURE_BACKOFF,
        MIN_ATTEMPT_TIMEOUT,
    )
    .is_err());
    assert!(RuleCoordinatorConfig::new(
        MIN_SUCCESS_INTERVAL,
        MIN_FAILURE_BACKOFF,
        MIN_FAILURE_BACKOFF,
        MAX_ATTEMPT_TIMEOUT + Duration::from_nanos(1),
    )
    .is_err());

    assert!(RuleCoordinator::new_for_mode(RuntimeMode::Development, config()).is_ok());
    assert!(RuleCoordinator::new_for_mode(RuntimeMode::Beta, config()).is_err());
    assert!(RuleCoordinator::new_for_mode(RuntimeMode::Mainnet, config()).is_err());

    let request = RuleSnapshotRequest {
        entries: vec![RuleSyncEntry {
            expected_manifest_sha256: "SENSITIVE-HASH".to_string(),
            manifest_json: "SENSITIVE-MANIFEST".to_string(),
            constructor_json: "SENSITIVE-CONSTRUCTOR".to_string(),
            address: "SENSITIVE-ADDRESS".to_string(),
        }],
        empty_snapshot_order: None,
    };
    assert!(!format!("{request:?}").contains("SENSITIVE"));
    assert_eq!(
        RuleCoordinatorError.to_string(),
        "RuleStorage sync coordinator failed"
    );
}

#[tokio::test(start_paused = true)]
async fn initial_success_stops_without_detached_mutation() {
    let coordinator = RuleCoordinator::new(config()).unwrap();
    let store = MemoryStore::default();
    let provider = SequenceProvider::empty(1);
    let mut scanner = scanner_with_old_rule();

    let (result, mid) = run_until(
        &coordinator,
        Target::Successes(1),
        &store,
        &mut scanner,
        &PanicContentSource,
        &PanicObservationSource,
        &provider,
    )
    .await;
    result.unwrap();
    assert_eq!(mid.phase, RuleCoordinatorPhase::Sleeping);
    assert_eq!(mid.last_outcome, Some(RuleCoordinatorOutcome::Succeeded));
    assert_eq!(mid.attempts, 1);
    assert_eq!(mid.successes, 1);
    assert_eq!(mid.failures, 0);
    assert_eq!(scanner.rule_count(), 0);
    assert_eq!(store.replacement_count(), 1);
    let checkpoint = store.bytes();

    sleep(Duration::from_secs(60)).await;
    assert_eq!(provider.call_count(), 1);
    assert_eq!(store.bytes(), checkpoint);
    assert_eq!(coordinator.status().phase, RuleCoordinatorPhase::Idle);
    assert_eq!(
        coordinator.status().last_outcome,
        Some(RuleCoordinatorOutcome::Cancelled)
    );
}

#[tokio::test(start_paused = true)]
async fn exact_replay_and_forward_update_are_restart_safe() {
    let coordinator = RuleCoordinator::new(config()).unwrap();
    let store = MemoryStore::default();
    let mut scanner = scanner_with_old_rule();

    run_until(
        &coordinator,
        Target::Successes(1),
        &store,
        &mut scanner,
        &PanicContentSource,
        &PanicObservationSource,
        &SequenceProvider::empty(10),
    )
    .await
    .0
    .unwrap();
    let first = store.bytes();
    assert_eq!(store.replacement_count(), 1);

    run_until(
        &coordinator,
        Target::Successes(2),
        &store,
        &mut scanner,
        &PanicContentSource,
        &PanicObservationSource,
        &SequenceProvider::empty(10),
    )
    .await
    .0
    .unwrap();
    assert_eq!(store.bytes(), first);
    assert_eq!(store.replacement_count(), 1);

    run_until(
        &coordinator,
        Target::Successes(3),
        &store,
        &mut scanner,
        &PanicContentSource,
        &PanicObservationSource,
        &SequenceProvider::empty(11),
    )
    .await
    .0
    .unwrap();
    assert_ne!(store.bytes(), first);
    assert_eq!(store.replacement_count(), 2);
}

#[tokio::test(start_paused = true)]
async fn transient_failures_back_off_and_recover() {
    let coordinator = RuleCoordinator::new(config()).unwrap();
    let store = MemoryStore::default();
    let provider = SequenceProvider::new([
        ProviderStep::Fail,
        ProviderStep::Fail,
        ProviderStep::Fail,
        ProviderStep::Empty(1),
    ]);
    let mut scanner = scanner_with_old_rule();

    let (result, mid) = run_until(
        &coordinator,
        Target::Successes(1),
        &store,
        &mut scanner,
        &PanicContentSource,
        &PanicObservationSource,
        &provider,
    )
    .await;
    result.unwrap();
    assert_eq!(mid.failures, 3);
    assert_eq!(mid.consecutive_failures, 0);
    let calls = provider.call_instants();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[1] - calls[0], INITIAL_BACKOFF);
    assert_eq!(calls[2] - calls[1], INITIAL_BACKOFF * 2);
    assert_eq!(calls[3] - calls[2], MAX_BACKOFF);
    assert_eq!(scanner.rule_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn timed_out_attempt_is_dropped_before_recovery() {
    let coordinator = RuleCoordinator::new(config()).unwrap();
    let store = MemoryStore::default();
    let provider = SequenceProvider::new([ProviderStep::Pending, ProviderStep::Empty(1)]);
    let mut scanner = scanner_with_old_rule();

    let (result, mid) = run_until(
        &coordinator,
        Target::Successes(1),
        &store,
        &mut scanner,
        &PanicContentSource,
        &PanicObservationSource,
        &provider,
    )
    .await;
    result.unwrap();
    assert_eq!(mid.failures, 1);
    assert_eq!(mid.successes, 1);
    let calls = provider.call_instants();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1] - calls[0], ATTEMPT_TIMEOUT + INITIAL_BACKOFF);
    assert_eq!(scanner.rule_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn shutdown_during_pending_attempt_preserves_state() {
    let coordinator = RuleCoordinator::new(config()).unwrap();
    let store = MemoryStore::default();
    let provider = SequenceProvider::new([ProviderStep::Pending]);
    let mut scanner = scanner_with_old_rule();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let driver = async {
        while provider.call_count() == 0 {
            sleep(Duration::from_millis(1)).await;
        }
        let _ = shutdown_tx.send(true);
    };
    let run = coordinator.run(
        &mut shutdown_rx,
        &store,
        &mut scanner,
        &PanicContentSource,
        &PanicObservationSource,
        &provider,
    );
    let (result, ()) = tokio::join!(run, driver);
    result.unwrap();
    assert!(old_rule_is_intact(&scanner));
    assert!(store.bytes().is_none());
    assert_eq!(coordinator.status().failures, 0);

    sleep(Duration::from_secs(60)).await;
    assert_eq!(provider.call_count(), 1);
    assert!(store.bytes().is_none());
}

#[tokio::test(start_paused = true)]
async fn rollback_and_same_order_equivocation_fail_closed() {
    for order in [9, 10] {
        let coordinator = RuleCoordinator::new(config()).unwrap();
        let store = MemoryStore::default();
        store.seed(10, 'a');
        let before = store.bytes();
        let provider = SequenceProvider::empty(order);
        let mut scanner = scanner_with_old_rule();

        let (result, mid) = run_until(
            &coordinator,
            Target::Failures(1),
            &store,
            &mut scanner,
            &PanicContentSource,
            &PanicObservationSource,
            &provider,
        )
        .await;
        result.unwrap();
        assert_eq!(mid.last_outcome, Some(RuleCoordinatorOutcome::Failed));
        assert_eq!(mid.failures, 1);
        assert!(old_rule_is_intact(&scanner));
        assert_eq!(store.bytes(), before);
        assert_eq!(store.replacement_count(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn duplicate_run_fails_and_guard_allows_sequential_rerun() {
    let coordinator = RuleCoordinator::new(config()).unwrap();
    let store_one = MemoryStore::default();
    let store_two = MemoryStore::default();
    let pending = SequenceProvider::new([ProviderStep::Pending]);
    let unused = SequenceProvider::empty(1);
    let mut scanner_one = scanner_with_old_rule();
    let mut scanner_two = scanner_with_old_rule();
    let (shutdown_tx, mut shutdown_one) = watch::channel(false);
    let (_unused_tx, mut shutdown_two) = watch::channel(false);

    let driver = async {
        while pending.call_count() == 0 {
            sleep(Duration::from_millis(1)).await;
        }
        let _ = shutdown_tx.send(true);
    };
    let first = coordinator.run(
        &mut shutdown_one,
        &store_one,
        &mut scanner_one,
        &PanicContentSource,
        &PanicObservationSource,
        &pending,
    );
    let second = coordinator.run(
        &mut shutdown_two,
        &store_two,
        &mut scanner_two,
        &PanicContentSource,
        &PanicObservationSource,
        &unused,
    );
    let (first_result, second_result, ()) = tokio::join!(first, second, driver);
    first_result.unwrap();
    assert_eq!(second_result, Err(RuleCoordinatorError));
    assert_eq!(unused.call_count(), 0);

    let valid = SequenceProvider::empty(1);
    run_until(
        &coordinator,
        Target::Successes(1),
        &store_one,
        &mut scanner_one,
        &PanicContentSource,
        &PanicObservationSource,
        &valid,
    )
    .await
    .0
    .unwrap();
    assert_eq!(valid.call_count(), 1);
}

#[tokio::test(start_paused = true)]
async fn dropping_run_future_releases_guard_and_allows_restart() {
    let coordinator = RuleCoordinator::new(config()).unwrap();
    let store = MemoryStore::default();
    let pending = SequenceProvider::new([ProviderStep::Pending]);
    let mut scanner = scanner_with_old_rule();
    let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let mut run = Box::pin(coordinator.run(
        &mut shutdown_rx,
        &store,
        &mut scanner,
        &PanicContentSource,
        &PanicObservationSource,
        &pending,
    ));
    tokio::select! {
        result = &mut run => panic!("pending run completed unexpectedly: {result:?}"),
        _ = sleep(Duration::from_millis(1)) => {}
    }
    assert_eq!(pending.call_count(), 1);
    drop(run);
    assert_eq!(coordinator.status().phase, RuleCoordinatorPhase::Idle);

    let valid = SequenceProvider::empty(1);
    run_until(
        &coordinator,
        Target::Successes(1),
        &store,
        &mut scanner,
        &PanicContentSource,
        &PanicObservationSource,
        &valid,
    )
    .await
    .0
    .unwrap();
    assert_eq!(valid.call_count(), 1);
    assert_eq!(scanner.rule_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn preset_shutdown_performs_no_attempt() {
    let coordinator = RuleCoordinator::new(config()).unwrap();
    let store = MemoryStore::default();
    let provider = SequenceProvider::empty(1);
    let mut scanner = scanner_with_old_rule();
    let (_shutdown_tx, mut shutdown_rx) = watch::channel(true);

    coordinator
        .run(
            &mut shutdown_rx,
            &store,
            &mut scanner,
            &PanicContentSource,
            &PanicObservationSource,
            &provider,
        )
        .await
        .unwrap();
    assert_eq!(provider.call_count(), 0);
    assert!(old_rule_is_intact(&scanner));
    assert!(store.bytes().is_none());
}
