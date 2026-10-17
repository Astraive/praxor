//! A bounded FIFO of owned writes. The writer mutex protects WAL/publication;
//! this mutex only protects admission, closed-group membership and completion.
use crate::config::WalSyncPolicy;
use crate::errors::{PraxisError, Result};
use crate::metrics::EngineMetrics;
use crate::transactions::WriteBatch;
use crate::types::{Key, ReadSnapshot};
use parking_lot::{Condvar, Mutex};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

const MAX_PENDING_REQUESTS: usize = 64;

pub(crate) enum WriteCondition {
    Unconditional,
    CompareAndSwap { key: Key, expected: Option<Vec<u8>> },
    Optimistic { snapshot: ReadSnapshot },
}

pub(crate) struct CommitRequest {
    pub(crate) batch: WriteBatch,
    pub(crate) condition: WriteCondition,
    pub(crate) encoded_len: usize,
    admitted_at: Instant,
    result: Mutex<Option<Result<u64>>>,
}

#[derive(Default)]
struct CommitState {
    queue: VecDeque<Arc<CommitRequest>>,
    in_flight: Vec<Arc<CommitRequest>>,
    pending_bytes: usize,
    pending_count: usize,
    next_ticket: u128,
    serving_ticket: u128,
    leader_active: bool,
    poison: Option<String>,
}

pub(crate) struct GroupCommitCoordinator {
    state: Mutex<CommitState>,
    ready: Condvar,
    max_pending: usize,
    max_pending_bytes: usize,
    max_group_bytes: usize,
}

pub(crate) enum CommitTurn<'a> {
    Complete(Result<u64>),
    Lead(CommitLeader<'a>),
}

/// Dropping an unfinished leader, including during unwinding, completes every
/// waiter with an ambiguous-write error. Reads retain the last published view.
pub(crate) struct CommitLeader<'a> {
    coordinator: &'a GroupCommitCoordinator,
    finished: bool,
}

impl GroupCommitCoordinator {
    pub(crate) fn new(wal_segment_bytes: usize) -> Self {
        Self::with_limits(
            MAX_PENDING_REQUESTS,
            wal_segment_bytes.max(1),
            wal_segment_bytes.saturating_sub(16).max(1),
        )
    }

    fn with_limits(max_pending: usize, max_pending_bytes: usize, max_group_bytes: usize) -> Self {
        Self {
            state: Mutex::new(CommitState::default()),
            ready: Condvar::new(),
            max_pending,
            max_pending_bytes,
            max_group_bytes,
        }
    }

    pub(crate) fn ensure_writable(&self) -> Result<()> {
        match &self.state.lock().poison {
            Some(_) => Err(PraxisError::RecoveryRequired),
            None => Ok(()),
        }
    }

    pub(crate) fn admit(
        &self,
        batch: WriteBatch,
        condition: WriteCondition,
        encoded_len: usize,
        metrics: &EngineMetrics,
    ) -> Result<Arc<CommitRequest>> {
        let admitted_at = Instant::now();
        let mut state = self.state.lock();
        let ticket = state.next_ticket;
        state.next_ticket += 1;
        loop {
            if state.poison.is_some() {
                return Err(PraxisError::RecoveryRequired);
            }
            // An oversized valid request is admitted alone. Count and byte
            // limits include the closed group currently doing IO/publication.
            let fits = state.pending_count == 0
                || (state.pending_count < self.max_pending
                    && encoded_len <= self.max_pending_bytes.saturating_sub(state.pending_bytes));
            if ticket == state.serving_ticket && fits {
                let request = Arc::new(CommitRequest {
                    batch,
                    condition,
                    encoded_len,
                    admitted_at,
                    result: Mutex::new(None),
                });
                state.pending_bytes += encoded_len;
                state.pending_count += 1;
                state.serving_ticket += 1;
                state.queue.push_back(request.clone());
                metrics.write_admissions.fetch_add(1, Ordering::Relaxed);
                self.ready.notify_all();
                return Ok(request);
            }
            self.ready.wait(&mut state);
        }
    }

    pub(crate) fn wait<'a>(&'a self, request: &CommitRequest) -> CommitTurn<'a> {
        let mut state = self.state.lock();
        loop {
            if let Some(result) = request.result.lock().take() {
                return CommitTurn::Complete(result);
            }
            if !state.leader_active && !state.queue.is_empty() {
                state.leader_active = true;
                return CommitTurn::Lead(CommitLeader {
                    coordinator: self,
                    finished: false,
                });
            }
            self.ready.wait(&mut state);
        }
    }

    pub(crate) fn poison(&self, reason: String) {
        let mut state = self.state.lock();
        state.poison.get_or_insert(reason);
        let mut requests = std::mem::take(&mut state.in_flight);
        requests.extend(state.queue.drain(..));
        for request in requests {
            *request.result.lock() = Some(Err(PraxisError::RecoveryRequired));
        }
        state.pending_bytes = 0;
        state.pending_count = 0;
        state.leader_active = false;
        self.ready.notify_all();
    }
}

impl CommitLeader<'_> {
    /// Call only after obtaining the writer mutex. No arrivals are added to
    /// this closed group once it has been drained, even if its sync is slow.
    pub(crate) fn drain(
        &self,
        policy: WalSyncPolicy,
        metrics: &EngineMetrics,
    ) -> Vec<Arc<CommitRequest>> {
        let mut state = self.coordinator.state.lock();
        let mut group: Vec<Arc<CommitRequest>> = Vec::new();
        let mut bytes = 0usize;
        while let Some(request) = state.queue.front() {
            if !group.is_empty()
                && (!matches!(policy, WalSyncPolicy::GroupCommit)
                    || !matches!(request.condition, WriteCondition::Unconditional)
                    || !matches!(group[0].condition, WriteCondition::Unconditional)
                    || request.encoded_len > self.coordinator.max_group_bytes.saturating_sub(bytes))
            {
                break;
            }
            let request = state.queue.pop_front().expect("front exists");
            bytes += request.encoded_len;
            metrics.commit_queue_wait_ns.fetch_add(
                request
                    .admitted_at
                    .elapsed()
                    .as_nanos()
                    .min(u64::MAX as u128) as u64,
                Ordering::Relaxed,
            );
            group.push(request);
        }
        state.in_flight.clone_from(&group);
        group
    }

    pub(crate) fn finish(mut self, results: Vec<Result<u64>>) {
        let mut state = self.coordinator.state.lock();
        // A poison operation already completed this group's requests. Do not
        // overwrite those results if failure was detected outside the leader.
        if state.poison.is_some() {
            self.finished = true;
            return;
        }
        let requests = std::mem::take(&mut state.in_flight);
        assert_eq!(requests.len(), results.len());
        for (request, result) in requests.into_iter().zip(results) {
            state.pending_count -= 1;
            state.pending_bytes -= request.encoded_len;
            *request.result.lock() = Some(result);
        }
        state.leader_active = false;
        self.finished = true;
        self.coordinator.ready.notify_all();
    }

    pub(crate) fn fail(mut self, reason: String) {
        self.coordinator.poison(reason);
        self.finished = true;
    }
}

impl Drop for CommitLeader<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.coordinator
                .poison("core commit leader unwound before completing its group".to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn request(
        coordinator: &GroupCommitCoordinator,
        metrics: &EngineMetrics,
        bytes: usize,
        condition: WriteCondition,
    ) -> Arc<CommitRequest> {
        coordinator
            .admit(WriteBatch::new(), condition, bytes, metrics)
            .unwrap()
    }

    fn lead<'a>(
        coordinator: &'a GroupCommitCoordinator,
        request: &CommitRequest,
    ) -> CommitLeader<'a> {
        match coordinator.wait(request) {
            CommitTurn::Lead(leader) => leader,
            CommitTurn::Complete(_) => panic!("request unexpectedly completed"),
        }
    }

    fn wait_until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !condition() {
            assert!(Instant::now() < deadline, "coordinator progress timed out");
            std::thread::yield_now();
        }
    }

    #[test]
    fn closed_groups_stop_at_conditions_and_byte_limit() {
        let coordinator = GroupCommitCoordinator::with_limits(8, 100, 30);
        let metrics = EngineMetrics::default();
        let first = request(&coordinator, &metrics, 20, WriteCondition::Unconditional);
        let second = request(&coordinator, &metrics, 20, WriteCondition::Unconditional);
        let conditional = request(
            &coordinator,
            &metrics,
            20,
            WriteCondition::Optimistic {
                snapshot: ReadSnapshot { sequence: 0 },
            },
        );
        let last = request(&coordinator, &metrics, 20, WriteCondition::Unconditional);
        for expected in [&first, &second, &conditional, &last] {
            let leader = lead(&coordinator, expected);
            let group = leader.drain(WalSyncPolicy::GroupCommit, &metrics);
            assert_eq!(group.len(), 1);
            assert!(Arc::ptr_eq(&group[0], expected));
            leader.finish(vec![Ok(1)]);
        }
    }

    #[test]
    fn later_arrival_cannot_complete_with_previously_closed_group() {
        let coordinator = GroupCommitCoordinator::with_limits(8, 100, 100);
        let metrics = EngineMetrics::default();
        let first = request(&coordinator, &metrics, 20, WriteCondition::Unconditional);
        let leader = lead(&coordinator, &first);
        assert_eq!(leader.drain(WalSyncPolicy::GroupCommit, &metrics).len(), 1);
        let later = request(&coordinator, &metrics, 20, WriteCondition::Unconditional);
        leader.finish(vec![Ok(1)]);
        assert!(later.result.lock().is_none());
        let leader = lead(&coordinator, &later);
        assert_eq!(leader.drain(WalSyncPolicy::GroupCommit, &metrics).len(), 1);
        leader.finish(vec![Ok(2)]);
        assert!(matches!(
            coordinator.wait(&later),
            CommitTurn::Complete(Ok(2))
        ));
    }

    #[test]
    fn oversized_admission_waits_for_closed_group_and_keeps_ticket_order() {
        let coordinator = Arc::new(GroupCommitCoordinator::with_limits(2, 100, 100));
        let metrics = Arc::new(EngineMetrics::default());
        let first = request(&coordinator, &metrics, 40, WriteCondition::Unconditional);
        request(&coordinator, &metrics, 40, WriteCondition::Unconditional);
        let leader = lead(&coordinator, &first);
        assert_eq!(leader.drain(WalSyncPolicy::GroupCommit, &metrics).len(), 2);
        let (sent, received) = std::sync::mpsc::channel();
        let large = {
            let coordinator = coordinator.clone();
            let metrics = metrics.clone();
            let sent = sent.clone();
            std::thread::spawn(move || {
                let request = request(&coordinator, &metrics, 150, WriteCondition::Unconditional);
                sent.send(("large", request)).unwrap();
            })
        };
        wait_until(|| coordinator.state.lock().next_ticket == 3);
        let small = {
            let coordinator = coordinator.clone();
            let metrics = metrics.clone();
            std::thread::spawn(move || {
                let request = request(&coordinator, &metrics, 1, WriteCondition::Unconditional);
                sent.send(("small", request)).unwrap();
            })
        };
        wait_until(|| coordinator.state.lock().next_ticket == 4);
        assert!(received.try_recv().is_err());
        leader.finish(vec![Ok(1), Ok(2)]);
        let (name, large_request) = received.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(name, "large");
        assert!(received.try_recv().is_err());
        let leader = lead(&coordinator, &large_request);
        assert_eq!(leader.drain(WalSyncPolicy::GroupCommit, &metrics).len(), 1);
        leader.finish(vec![Ok(3)]);
        let (name, _) = received.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(name, "small");
        large.join().unwrap();
        small.join().unwrap();
    }

    #[test]
    fn leader_unwind_completes_queued_and_backpressured_waiters() {
        let coordinator = Arc::new(GroupCommitCoordinator::with_limits(2, 100, 100));
        let metrics = Arc::new(EngineMetrics::default());
        let first = request(&coordinator, &metrics, 40, WriteCondition::Unconditional);
        let second = request(&coordinator, &metrics, 40, WriteCondition::Unconditional);
        let leader = lead(&coordinator, &first);
        assert_eq!(leader.drain(WalSyncPolicy::EveryBatch, &metrics).len(), 1);
        let follower = {
            let coordinator = coordinator.clone();
            std::thread::spawn(move || match coordinator.wait(&second) {
                CommitTurn::Complete(result) => result,
                CommitTurn::Lead(_) => panic!("poisoned waiter became leader"),
            })
        };
        let admission = {
            let coordinator = coordinator.clone();
            let metrics = metrics.clone();
            std::thread::spawn(move || {
                coordinator
                    .admit(
                        WriteBatch::new(),
                        WriteCondition::Unconditional,
                        1,
                        &metrics,
                    )
                    .map(|_| ())
            })
        };
        wait_until(|| coordinator.state.lock().next_ticket == 3);
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _leader = leader;
            panic!("simulated leader unwind");
        }));
        assert!(unwind.is_err());
        assert!(matches!(
            follower.join().unwrap(),
            Err(PraxisError::RecoveryRequired)
        ));
        assert!(matches!(
            admission.join().unwrap(),
            Err(PraxisError::RecoveryRequired)
        ));
        assert!(matches!(
            coordinator.wait(&first),
            CommitTurn::Complete(Err(PraxisError::RecoveryRequired))
        ));
        assert!(matches!(
            coordinator.ensure_writable(),
            Err(PraxisError::RecoveryRequired)
        ));
    }
}
