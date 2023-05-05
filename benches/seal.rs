use criterion::{criterion_group, criterion_main, Criterion};
use hapi_iron_oxide::{seal, typenum::U32};

pub fn seal_bench(c: &mut Criterion) {
    c.bench_function("seal with defaults", |b| {
        b.iter(|| {
            seal::<U32, String>(
                "{\"who\":\"dis\"}".to_string(),
                "passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword".to_string(),
                Default::default(),
            )
            .unwrap();
        })
    });
}

criterion_group!(benches, seal_bench);
criterion_main!(benches);
