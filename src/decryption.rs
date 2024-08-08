use ark_bls12_381::{Bls12_381, Config};
use ark_ec::{
    bls12::{Bls12, G1Prepared, G2Prepared}, pairing::{Pairing, PairingOutput}, VariableBaseMSM
};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
    Radix2EvaluationDomain,
};
use ark_std::{One, Zero};
use std::ops::Div;

use crate::{
    api::types::{E, G1, G2}, kzg::{UniversalParams, KZG10}, setup::{AggregateKey, PublicKey}, utils::{interp_mostly_zero, IsValidHelper}
};

struct Parameters {
    pub agg_key: AggregateKey<E>,
    pub b: DensePolynomial<<E as Pairing>::ScalarField>,
    pub b_evals: Vec<<E as Pairing>::ScalarField>,
    pub params: UniversalParams<E>,
}

pub async fn agg_dec<E: Pairing>(
    partial_decryptions: &[E::G2], //insert 0 if a party did not respond or verification failed
    sa1: &[E::G1; 2],
    sa2: &[E::G2; 6],
    t: usize,
    n: usize,
    selector: &[bool],
    agg_key: &AggregateKey<E>,
    params: &UniversalParams<E>,
) -> PairingOutput<E> {
    let domain = Radix2EvaluationDomain::<E::ScalarField>::new(n).unwrap();
    let domain_elements: Vec<E::ScalarField> = domain.elements().collect();
    // points is where B is set to zero
    // parties is the set of parties who have signed
    let mut points = vec![domain_elements[0]]; // 0 is the dummy party that is always true
    let mut parties: Vec<usize> = Vec::new(); // parties indexed from 0..n-1
    for i in 0..n {
        if selector[i] {
            parties.push(i);
        } else {
            points.push(domain_elements[i]);
        }
    }

    let b = interp_mostly_zero(E::ScalarField::one(), &points);
    let b_evals = domain.fft(&b.coeffs);

    debug_assert!(b.degree() == points.len() - 1);
    debug_assert!(b.evaluate(&domain_elements[0]) == E::ScalarField::one());

    let b_async = b.clone();
    let params_async = params.clone();
    // commit to b in g2
    let b_g2_task = tokio::spawn(async move {
        // let b_g2: E::G2 = 
        KZG10::<E, DensePolynomial<E::ScalarField>>::commit_g2(&params_async, &b_async)
            .unwrap()
    }).await;
    // let b_g2_output = tokio::join!(b_g2_task);

    // q0 = (b-1)/(x-domain_elements[0])
    let mut bminus1 = b.clone();
    bminus1.coeffs[0] -= E::ScalarField::one();

    debug_assert!(bminus1.evaluate(&domain_elements[0]) == E::ScalarField::zero());

    let xminus1 =
        DensePolynomial::from_coefficients_vec(vec![-domain_elements[0], E::ScalarField::one()]);
    let q0 = bminus1.div(&xminus1);

    let q0_g1: E::G1 = KZG10::<E, DensePolynomial<E::ScalarField>>::commit_g1(params, &q0)
        .unwrap()
        .into();

    // bhat = x^t * b
    // insert t 0s at the beginning of bhat.coeffs

    let b_async = b.clone();
    let agg_key_async = agg_key.clone();
    let params_async = params.clone();

    let bhat_g1_task = tokio::spawn(async move {
        let mut bhat_coeffs = vec![E::ScalarField::zero(); t];
        bhat_coeffs.append(&mut b_async.coeffs.clone());
        let bhat = DensePolynomial::from_coefficients_vec(bhat_coeffs);
        debug_assert_eq!(bhat.degree(), n - 1);

        // let bhat_g1: E::G1 =
        KZG10::<E, DensePolynomial<E::ScalarField>>::commit_g1(&params_async, &bhat)
            .unwrap()
    }).await;
    // let bhat_g1_output = tokio::join!(bhat_g1_task);

    let n_inv = E::ScalarField::one() / E::ScalarField::from((n) as u32);

    let b_evals_async = b_evals.clone();
    let parties_async = parties.clone();

    // compute the aggregate public key
    let apk_task = tokio::spawn(async move {
        let mut bases: Vec<<E as Pairing>::G1Affine> = Vec::new();
        let mut scalars: Vec<<E as Pairing>::ScalarField> = Vec::new();
        for &i in &parties_async {
            bases.push(agg_key_async.pk[i].bls_pk.into());
            scalars.push(b_evals_async[i]);
        }
        let mut apk = E::G1::msm(bases.as_slice(), scalars.as_slice()).unwrap();
        apk *= n_inv;
        apk
    }).await;
    // let apk_output = tokio::join!(apk_task);

    let b_evals_async = b_evals.clone();
    let partial_decryptions_async = partial_decryptions.to_vec().clone();
    let parties_async = parties.clone();

    let sigma_task = tokio::spawn(async move {
        // compute sigma = (\sum B(omega^i)partial_decryptions[i])/(n) for i in parties
        let mut bases: Vec<<E as Pairing>::G2Affine> = Vec::new();
        let mut scalars: Vec<<E as Pairing>::ScalarField> = Vec::new();
        for &i in &parties_async {
            bases.push(partial_decryptions_async[i].into());
            scalars.push(b_evals_async[i]);
        }
        let mut sigma = E::G2::msm(bases.as_slice(), scalars.as_slice()).unwrap();
        sigma *= n_inv;
        sigma
    }).await;

    let b_evals_async = b_evals.clone();
    let agg_key_async = agg_key.clone();
    let parties_async = parties.clone();

    let qx_task = tokio::spawn(async move {
        // compute Qx, Qhatx and Qz
        let mut bases: Vec<<E as Pairing>::G1Affine> = Vec::new();
        let mut scalars: Vec<<E as Pairing>::ScalarField> = Vec::new();
        for &i in &parties_async {
            bases.push(agg_key_async.pk[i].sk_li_by_tau.into());
            scalars.push(b_evals_async[i]);
        }
        // let qx =
        E::G1::msm(bases.as_slice(), scalars.as_slice()).unwrap()
    }).await;

    let b_evals_async = b_evals.clone();
    let parties_async = parties.clone();

    let qz_task = tokio::spawn(async move {
        let mut bases: Vec<<E as Pairing>::G1Affine> = Vec::new();
        let mut scalars: Vec<<E as Pairing>::ScalarField> = Vec::new();
        for &i in &parties_async {
            bases.push(agg_key_async.agg_sk_li_by_z[i].into());
            scalars.push(b_evals_async[i]);
        }
        // let qz =
        E::G1::msm(bases.as_slice(), scalars.as_slice()).unwrap()
    }).await;

    let b_evals_async = b_evals.clone();
    let agg_key_async = agg_key.clone();
    let parties_async = parties.clone();

    let qhatx_task = tokio::spawn(async move {
        let mut bases: Vec<<E as Pairing>::G1Affine> = Vec::new();
        let mut scalars: Vec<<E as Pairing>::ScalarField> = Vec::new();
        for &i in &parties_async {
            bases.push(agg_key_async.pk[i].sk_li_minus0.into());
            scalars.push(b_evals_async[i]);
        }
        // let qhatx =
        E::G1::msm(bases.as_slice(), scalars.as_slice()).unwrap()
    }).await;

    // e(w1||sa1, sa2||w2)
    let minus1 = -E::ScalarField::one();
    let w1 = [
        apk_task.unwrap() * (minus1),
        qz_task.unwrap() * (minus1),
        qx_task.unwrap().into() * (minus1),
        qhatx_task.unwrap(),
        bhat_g1_task.unwrap() * (minus1),
        q0_g1 * (minus1),
    ];
    let w2 = [b_g2_task.unwrap().into(), sigma_task.unwrap()];

    let mut enc_key_lhs = w1.to_vec();
    enc_key_lhs.append(&mut sa1.to_vec());

    let mut enc_key_rhs = sa2.to_vec();
    enc_key_rhs.append(&mut w2.to_vec());

    let enc_key = E::multi_pairing(enc_key_lhs, enc_key_rhs);

    enc_key
}

pub fn part_verify(gamma_g2: <Bls12_381 as Pairing>::G2, pk: PublicKey<Bls12_381>, g1: <Bls12_381 as Pairing>::G1, part_dec: <Bls12_381 as Pairing>::G2) -> bool {
    Bls12_381::pairing(pk.bls_pk, gamma_g2) == Bls12_381::pairing(g1, part_dec)
}

fn prepare_and_pair(hint: G1, prepared_g2: &G2Prepared<Config>, prepared_bls_pk: &G1Prepared<Config>, li_x: G2) -> bool {
    let prepared_hint = G1Prepared::from(hint);
    let prepared_li_x = G2Prepared::from(li_x);

    Bls12::pairing(prepared_hint, prepared_g2.clone()) == Bls12::pairing(prepared_bls_pk.clone(), prepared_li_x)
}

pub fn is_valid(pk: PublicKey<E>, n: usize, kzg_params: &UniversalParams<Bls12<ark_bls12_381::Config>>, helper: &IsValidHelper) -> bool {
    let prepared_g2 = G2Prepared::from(kzg_params.powers_of_h[0]);
    let prepared_bls_pk = G1Prepared::from(pk.bls_pk);

    if prepare_and_pair(pk.sk_li, &prepared_g2, &prepared_bls_pk, helper.li) == false {
        return false;
    }
    if prepare_and_pair(pk.sk_li_minus0, &prepared_g2, &prepared_bls_pk, helper.li_minus0) == false {
        return false;
    }
    if prepare_and_pair(pk.sk_li_by_tau, &prepared_g2, &prepared_bls_pk, helper.li_by_tau) == false {
        return false;
    }
    for i in 0..n {
        if prepare_and_pair(pk.sk_li_by_z[i], &prepared_g2, &prepared_bls_pk, helper.li_by_z[i]) == false {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        encryption::encrypt,
        kzg::KZG10,
        setup::{PublicKey, SecretKey}, utils::lagrange_poly,
    };
    use ark_ec::bls12::Bls12;
    use ark_poly::univariate::DensePolynomial;

    type E = ark_bls12_381::Bls12_381;
    type G2 = <E as Pairing>::G2;
    type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

    #[test]
    fn test_decryption() {
        let mut rng = ark_std::test_rng();
        let n = 16; // actually n-1 total parties. one party is a dummy party that is always true
        let t: usize = 15;
        debug_assert!(t < n);

        let params = KZG10::<E, UniPoly381>::setup(n, &mut rng).unwrap();

        let mut sk: Vec<SecretKey<E>> = Vec::new();
        let mut pk: Vec<PublicKey<E>> = Vec::new();

        let lagrange_polys: Vec<DensePolynomial<<Bls12<ark_bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField>> = (0..n)
            .map(|j| lagrange_poly(n, j))
            .collect();

        // create the dummy party's keys
        sk.push(SecretKey::<E>::new(&mut rng));
        sk[0].nullify();
        pk.push(sk[0].get_pk(0, &params, n, &lagrange_polys));

        for i in 1..n {
            sk.push(SecretKey::<E>::new(&mut rng));
            pk.push(sk[i].get_pk(i, &params, n, &lagrange_polys))
        }

        let agg_key = AggregateKey::<E>::new(pk, n, &params);
        let ct = encrypt::<E>(&agg_key, t, &params);

        // compute partial decryptions
        let mut partial_decryptions: Vec<G2> = Vec::new();
        for i in 0..t + 1 {
            partial_decryptions.push(sk[i].partial_decryption(ct.gamma_g2));
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

        let _dec_key = agg_dec(&partial_decryptions, &ct.sa1, &ct.sa2, ct.t, n, &selector, &agg_key, &params);
    }
}
