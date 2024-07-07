use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_poly::univariate::DensePolynomial;
use ark_std::Zero;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use silent_threshold::{
    encryption::encrypt,
    kzg::KZG10,
    setup::{AggregateKey, PublicKey, SecretKey}, utils::lagrange_poly,
};

type E = ark_bls12_381::Bls12_381;
type G2 = <E as Pairing>::G2;
type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

fn bench_decrypt(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();
    let mut group = c.benchmark_group("decrypt");

    for size in 3..=10 {
        let n = 1 << size; // actually n-1 total parties. one party is a dummy party that is always true
        let t: usize = n / 2;

        let params = KZG10::<E, UniPoly381>::setup(n, &mut rng).unwrap();

        let mut sk: Vec<SecretKey<E>> = Vec::new();
        let mut pk: Vec<PublicKey<E>> = Vec::new();

        let lagrange_polys: Vec<DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>> = (0..n)
            .map(|j| lagrange_poly(n, j))
            .collect();

        // create the dummy party's keys
        sk.push(SecretKey::<E>::new(&mut rng));
        sk[0].nullify();
        pk.push(sk[0].get_pk(0, &params, n, &lagrange_polys));

        // for i in 1..n {
        //     sk.push(SecretKey::<E>::new(&mut rng));
        //     pk.push(sk[i].get_pk(i, &params, n));
        // }

        sk.push(SecretKey::<E>::new(&mut rng));
        pk.push(sk[1].get_pk(1, &params, n, &lagrange_polys));

        for _ in 2..n {
            sk.push(sk[1].clone());
            pk.push(pk[1].clone());
        }

        println!("Setup keys!");

        let agg_key = AggregateKey::<E>::new(pk, n, &params);
        let ct = encrypt::<E>(&agg_key, t, &params);

        // compute partial decryptions
        let mut partial_decryptions: Vec<G2> = Vec::new();
        for i in 0..t + 1 {
            partial_decryptions.push(sk[i].partial_decryption(&ct));
        }
        for _ in t + 1..n {
            partial_decryptions.push(G2::zero());
        }

        // compute the decryption key
        let mut selector: Vec<bool> = Vec::new();
        for _ in 0..t + 1 {
            selector.push(true);
        }
        for _ in t + 1..n {
            selector.push(false);
        }

        group.bench_with_input(
            BenchmarkId::from_parameter(n),
            &(partial_decryptions, ct, selector, agg_key, params),
            |_, _| {
                //b.iter(|| agg_dec(&inp.0, &inp.1, &inp.2, &inp.3, &inp.4));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_decrypt);
criterion_main!(benches);
