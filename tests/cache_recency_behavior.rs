use bytes::Bytes;
use praxis::cache::BlockCache;
use std::collections::VecDeque;

#[test]
fn long_mixed_history_matches_an_exact_lru_reference() {
    const BUDGET: usize = 17;
    let mut cache = BlockCache::new(BUDGET);
    // A small independent model keeps precisely one item per resident key.
    let mut reference: VecDeque<(usize, Bytes)> = VecDeque::new();
    let mut random = 0x4c52_5521_u64;
    for step in 0..50_000 {
        random = random
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let key = (random >> 32) as usize % 31;
        match random % 11 {
            0..=4 => {
                let length = (random >> 17) as usize % 26;
                let value = Bytes::from(vec![step as u8; length]);
                if let Some(position) = reference.iter().position(|entry| entry.0 == key) {
                    reference.remove(position);
                }
                reference.push_back((key, value.clone()));
                let mut expected_evicted = Vec::new();
                while reference
                    .iter()
                    .map(|entry| entry.1.len().max(1))
                    .sum::<usize>()
                    > BUDGET
                {
                    expected_evicted.push(reference.pop_front().unwrap());
                }
                assert_eq!(
                    cache.insert_with_evicted(key, value),
                    expected_evicted,
                    "step {step}"
                );
            }
            5..=9 => {
                let expected = reference
                    .iter()
                    .position(|entry| entry.0 == key)
                    .map(|position| {
                        let entry = reference.remove(position).unwrap();
                        let value = entry.1.clone();
                        reference.push_back(entry);
                        value
                    });
                assert_eq!(cache.get(&key), expected, "step {step}");
            }
            _ => {
                reference.retain(|entry| entry.0 % 3 != key % 3);
                cache.retain(|candidate| candidate % 3 != key % 3);
            }
        }
        assert_eq!(cache.len(), reference.len(), "step {step}");
        assert_eq!(
            cache.current_bytes(),
            reference.iter().map(|entry| entry.1.len()).sum::<usize>()
        );
        for candidate in 0..31 {
            let expected = reference.iter().find(|entry| entry.0 == candidate);
            assert_eq!(
                cache.contains_key(&candidate),
                expected.is_some(),
                "step {step}"
            );
            assert_eq!(
                cache.value_len(&candidate),
                expected.map(|entry| entry.1.len()),
                "step {step}"
            );
        }
    }
}
