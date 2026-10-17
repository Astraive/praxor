use bytes::Bytes;
use criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main,
};
use praxis::wal::WalRecord;
use praxis::{PraxisConfig, PraxisEngine, WriteBatch};
use tempfile::tempdir;

fn record_sizing(c: &mut Criterion) {
    let mut group = c.benchmark_group("record_sizing");
    for count in [1, 16, 256] {
        let mut batch = WriteBatch::new();
        for index in 0..count {
            batch.put_default(
                Bytes::from(format!("key/{index}")),
                Bytes::from(vec![42; 128]),
            );
        }
        let record = WalRecord { sequence: 1, batch };
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(BenchmarkId::from_parameter(count), &record, |b, record| {
            b.iter(|| black_box(black_box(record).encoded_len()));
        });
    }
    group.finish();
}

fn independent_durable_puts(c: &mut Criterion) {
    let mut group = c.benchmark_group("independent_durable_puts");
    for count in [1, 16, 256] {
        let keys = (0..count)
            .map(|index| Bytes::from(format!("key/{index}")))
            .collect::<Vec<_>>();
        let value = Bytes::from(vec![42; 128]);
        group.throughput(Throughput::Elements(count));
        group.bench_function(BenchmarkId::new("every_batch", count), |b| {
            b.iter_batched(
                || {
                    let dir = tempdir().unwrap();
                    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
                    (engine, dir)
                },
                |(engine, dir)| {
                    for key in &keys {
                        engine.put(key.clone(), value.clone()).unwrap();
                    }
                    black_box(engine.snapshot().sequence);
                    // Criterion drops outputs after timing, excluding filesystem
                    // cleanup from the commit measurement as well as setup.
                    (engine, dir)
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

fn actual_write_batches(c: &mut Criterion) {
    let mut group = c.benchmark_group("actual_write_batches");
    for count in [1, 16, 256] {
        let mut batch = WriteBatch::new();
        for index in 0..count {
            batch.put_default(format!("key/{index}"), Bytes::from(vec![42; 128]));
        }
        group.throughput(Throughput::Elements(count));
        group.bench_function(BenchmarkId::new("every_batch_empty_engine", count), |b| {
            b.iter_batched(
                || {
                    let dir = tempdir().unwrap();
                    let engine = PraxisEngine::open(PraxisConfig::new(dir.path())).unwrap();
                    (engine, dir, batch.clone())
                },
                |(engine, dir, batch)| {
                    black_box(engine.write_batch(batch).unwrap());
                    // Returning ownership excludes engine/directory cleanup.
                    (engine, dir)
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    record_sizing,
    independent_durable_puts,
    actual_write_batches
);
criterion_main!(benches);
