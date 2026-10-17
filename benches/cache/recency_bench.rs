use bytes::Bytes;
use parking_lot::Mutex;
use praxis::cache::BlockCache;
use std::hint::black_box;
use std::sync::{Arc, Barrier};
use std::time::Instant;

type Key = Box<[u8]>;

#[derive(Clone, Copy)]
enum Workload {
    Hit,
    Overwrite,
    Mixed,
}

impl Workload {
    fn name(self, mutex: bool) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Overwrite => "overwrite",
            Self::Mixed if mutex => "mixed_pair",
            Self::Mixed => "mixed_eviction",
        }
    }

    fn calls_per_lock(self) -> usize {
        match self {
            Self::Mixed => 2,
            _ => 1,
        }
    }
}

fn verify(cache: &mut BlockCache<Key>, keys: &[Key], residents: usize) {
    assert_eq!(cache.len(), residents);
    assert_eq!(cache.current_bytes(), residents * 8);
    let mut found = 0;
    for key in keys {
        if let Some(value) = cache.get(key) {
            assert_eq!(value.as_ref(), b"payload8");
            found += 1;
        }
    }
    assert_eq!(found, residents);
}

fn prefill(keys: &[Key], residents: usize) -> BlockCache<Key> {
    let mut cache = BlockCache::new(residents * 8);
    for key in keys.iter().take(residents) {
        cache.insert(key.clone(), Bytes::from_static(b"payload8"));
    }
    cache
}

fn single(
    keys: &[Key],
    residents: usize,
    key_bytes: usize,
    calls: usize,
    repetition: usize,
    workload: Workload,
) {
    let mut cache = prefill(keys, residents);
    let started = Instant::now();
    for operation in 0..calls {
        match workload {
            Workload::Hit => {
                black_box(cache.get(&keys[operation & (residents - 1)]));
            }
            Workload::Overwrite => cache.insert(
                keys[operation & (residents - 1)].clone(),
                Bytes::from_static(b"payload8"),
            ),
            Workload::Mixed => {
                let index = ((operation / 2) + residents) & (residents * 2 - 1);
                if operation & 1 == 0 {
                    cache.insert(keys[index].clone(), Bytes::from_static(b"payload8"));
                } else {
                    black_box(cache.get(&keys[index]));
                }
            }
        }
    }
    let elapsed_ns = started.elapsed().as_nanos();
    verify(&mut cache, keys, residents);
    println!(
        "single,{},{residents},{key_bytes},1,{repetition},{calls},0,{elapsed_ns},{:.3},{:.6},,0",
        workload.name(false),
        elapsed_ns as f64 / calls as f64,
        calls as f64 * 1_000.0 / elapsed_ns as f64,
    );
}

fn contention(
    keys: &Arc<Vec<Key>>,
    residents: usize,
    key_bytes: usize,
    threads: usize,
    calls_per_thread: usize,
    repetition: usize,
    workload: Workload,
) {
    let calls_per_lock = workload.calls_per_lock();
    let iterations = calls_per_thread / calls_per_lock;
    let cache = Arc::new(Mutex::new(prefill(keys, residents)));
    let ready = Arc::new(Barrier::new(threads + 1));
    let start = Arc::new(Barrier::new(threads + 1));
    let finished = Arc::new(Barrier::new(threads + 1));
    let mut workers = Vec::with_capacity(threads);
    for worker in 0..threads {
        let offset = worker * 7_919;
        // Exclude caller-owned input construction and thread startup from timing.
        let inputs: Vec<Key> = match workload {
            Workload::Hit => Vec::new(),
            Workload::Overwrite => (0..iterations)
                .map(|operation| keys[(operation + offset) & (residents - 1)].clone())
                .collect(),
            Workload::Mixed => (0..iterations)
                .map(|operation| {
                    keys[(operation + residents + offset) & (residents * 2 - 1)].clone()
                })
                .collect(),
        };
        let cache = Arc::clone(&cache);
        let keys = Arc::clone(keys);
        let ready = Arc::clone(&ready);
        let start = Arc::clone(&start);
        let finished = Arc::clone(&finished);
        workers.push(std::thread::spawn(move || {
            let mut inputs = inputs.into_iter();
            let mut incorrect = 0;
            let mut checked_hits = 0;
            ready.wait();
            start.wait();
            let worker_started = Instant::now();
            for operation in 0..iterations {
                match workload {
                    Workload::Hit => {
                        let result = cache
                            .lock()
                            .get(&keys[(operation + offset) & (residents - 1)]);
                        incorrect += usize::from(result.as_deref() != Some(&b"payload8"[..]));
                        checked_hits += 1;
                        black_box(result);
                    }
                    Workload::Overwrite => cache.lock().insert(
                        inputs.next().expect("precreated input"),
                        Bytes::from_static(b"payload8"),
                    ),
                    Workload::Mixed => {
                        let key = inputs.next().expect("precreated input");
                        let lookup = &keys[(operation + residents + offset) & (residents * 2 - 1)];
                        let mut cache = cache.lock();
                        cache.insert(key, Bytes::from_static(b"payload8"));
                        // One guard keeps this validating read safe from eviction
                        // by other writers; each pair counts as two cache calls.
                        let result = cache.get(lookup);
                        incorrect += usize::from(result.as_deref() != Some(&b"payload8"[..]));
                        checked_hits += 1;
                        black_box(result);
                    }
                }
            }
            let worker_ns = worker_started.elapsed().as_nanos();
            finished.wait();
            drop(inputs);
            (worker_ns, incorrect, checked_hits)
        }));
    }
    ready.wait();
    let started = Instant::now();
    start.wait();
    finished.wait();
    let elapsed_ns = started.elapsed().as_nanos();
    let mut worker_ns = 0;
    let mut checked_hits = 0;
    for worker in workers {
        let (elapsed, incorrect, checked) = worker.join().expect("cache benchmark worker");
        assert_eq!(incorrect, 0, "cache returned an incorrect hit");
        worker_ns += elapsed;
        checked_hits += checked;
    }
    let calls = threads * calls_per_thread;
    let expected_hits = match workload {
        Workload::Hit => calls,
        Workload::Overwrite => 0,
        Workload::Mixed => calls / 2,
    };
    assert_eq!(checked_hits, expected_hits);
    verify(&mut cache.lock(), keys, residents);
    println!(
        "mutex,{},{residents},{key_bytes},{threads},{repetition},{calls},{calls_per_lock},{elapsed_ns},{:.3},{:.6},{:.3},{checked_hits}",
        workload.name(true),
        elapsed_ns as f64 / calls as f64,
        calls as f64 * 1_000.0 / elapsed_ns as f64,
        worker_ns as f64 / calls as f64,
    );
}

fn setting(name: &str, default: usize) -> usize {
    std::env::var(name).map_or(default, |value| {
        value.parse().expect("positive integer setting")
    })
}

fn main() {
    let mode = std::env::var("PRAXIS_CACHE_BENCH_MODE").unwrap_or_else(|_| "single".into());
    assert!(matches!(mode.as_str(), "single" | "mutex"));
    let mutex = mode == "mutex";
    let calls = setting(
        "PRAXIS_CACHE_BENCH_CALLS",
        if mutex { 65_536 } else { 1_048_576 },
    );
    let repetitions = setting("PRAXIS_CACHE_BENCH_REPETITIONS", 3);
    assert!(calls > 0 && calls.is_multiple_of(2) && repetitions > 0);
    let cases = if mutex {
        vec![(256, 8), (65_536, 256)]
    } else {
        [256, 4_096, 65_536]
            .into_iter()
            .flat_map(|resident| [8, 64, 256].into_iter().map(move |bytes| (resident, bytes)))
            .collect()
    };
    println!(
        "mode,workload,residents,key_bytes,threads,repetition,total_calls,calls_per_lock,elapsed_ns,wall_ns_per_call,million_calls_per_second,worker_mean_ns_per_call,checked_hits"
    );
    for (residents, key_bytes) in cases {
        let keys = Arc::new(
            (0..residents * 2)
                .map(|index| {
                    let mut key = vec![0x5a; key_bytes];
                    key[..8].copy_from_slice(&(index as u64).to_le_bytes());
                    key.into_boxed_slice()
                })
                .collect::<Vec<_>>(),
        );
        for workload in [Workload::Hit, Workload::Overwrite, Workload::Mixed] {
            for repetition in 0..repetitions {
                if mutex {
                    for threads in [1, 2, 4, 8, 16] {
                        contention(
                            &keys, residents, key_bytes, threads, calls, repetition, workload,
                        );
                    }
                } else {
                    single(&keys, residents, key_bytes, calls, repetition, workload);
                }
            }
        }
    }
}
