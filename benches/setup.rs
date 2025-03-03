use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_poly::univariate::DensePolynomial;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use silent_threshold::{kzg::KZG10, setup::SecretKey, utils::lagrange_poly};

type E = ark_bls12_381::Bls12_381;
type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

async fn bench_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("setup");
    group.sample_size(10);
    let mut rng = ark_std::test_rng();
    for size in 3..=10 {
        let n = 1 << size; // actually n-1 total parties. one party is a dummy party that is always true
        let params = KZG10::<E, UniPoly381>::setup(n, &mut rng).unwrap();

        let sk = SecretKey::<E>::new(&mut rng);

        let lagrange_polys: Vec<DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>> = (0..n)
            .map(|j| lagrange_poly(n, j))
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(n), &params, |b, inp| {
            b.iter(|| sk.get_pk(0, &inp, n, lagrange_polys.clone()).await);
        });
    }

    group.finish();
}

criterion_group!(benches, bench_setup);
criterion_main!(benches);
