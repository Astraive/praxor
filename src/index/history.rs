//! Retain every append decision visible at any raw sequence ceiling.
//!
//! A later append at S shadows an earlier append at T >= S for all ceilings:
//! whenever T is eligible, S is eligible and wins by append order. Records at
//! successively smaller sequences form all remaining possible decisions.

#[derive(Default)]
struct Frontier {
    minimum: Option<u64>,
}

impl Frontier {
    fn keep(&mut self, sequence: u64) -> bool {
        if self.minimum.is_none_or(|minimum| sequence < minimum) {
            self.minimum = Some(sequence);
            true
        } else {
            false
        }
    }
}

pub(crate) fn retain_snapshot_versions<T>(versions: &mut Vec<T>, sequence: impl Fn(&T) -> u64) {
    let mut frontier = Frontier::default();
    versions.reverse();
    versions.retain(|version| frontier.keep(sequence(version)));
    versions.reverse();
}

pub(crate) fn reclaimable_versions<T>(versions: &[T], sequence: impl Fn(&T) -> u64) -> u64 {
    let mut frontier = Frontier::default();
    versions
        .iter()
        .rev()
        .filter(|version| !frontier.keep(sequence(version)))
        .count() as u64
}

#[cfg(test)]
mod tests {
    use super::{reclaimable_versions, retain_snapshot_versions};

    // Select append identities by a forward visibility scan at every distinct
    // interval in the input alphabet. This model does not implement pruning.
    fn check(history: &[(u64, Option<u8>)]) {
        let mut selected = 0u8;
        for ceiling in [0, 1, 2, 3, u64::MAX - 1, u64::MAX] {
            let mut decision = None;
            for (index, &(sequence, _)) in history.iter().enumerate() {
                if sequence <= ceiling {
                    decision = Some(index);
                }
            }
            if let Some(index) = decision {
                selected |= 1 << index;
            }
        }
        let expected: Vec<_> = history
            .iter()
            .enumerate()
            .filter(|(index, _)| selected & (1 << index) != 0)
            .map(|(_, version)| *version)
            .collect();
        let estimate = reclaimable_versions(history, |version| version.0);
        let mut retained = history.to_vec();
        retain_snapshot_versions(&mut retained, |version| version.0);
        assert_eq!(retained, expected, "original history: {history:?}");
        assert_eq!(estimate, (history.len() - expected.len()) as u64);
        assert_eq!(reclaimable_versions(&retained, |version| version.0), 0);
        retain_snapshot_versions(&mut retained, |version| version.0);
        assert_eq!(retained, expected);
    }

    fn enumerate(history: &mut Vec<(u64, Option<u8>)>, count: &mut usize) {
        check(history);
        *count += 1;
        if history.len() == 5 {
            return;
        }
        for sequence in [0, 1, 2, u64::MAX] {
            for value in [None, Some(1), Some(2)] {
                history.push((sequence, value));
                enumerate(history, count);
                history.pop();
            }
        }
    }

    #[test]
    fn exhaustive_append_decisions_include_zero_max_duplicates_and_tombstones() {
        let mut count = 0;
        enumerate(&mut Vec::new(), &mut count);
        assert_eq!(count, 271_453);
    }
}
