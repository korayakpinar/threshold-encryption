use ark_bls12_381::Bls12_381;
use ark_ec::pairing::PairingOutput;
use ark_ec::{pairing::Pairing, Group};
use ark_poly::DenseUVPolynomial;
use ark_poly::{domain::EvaluationDomain, univariate::DensePolynomial, Radix2EvaluationDomain};
use ark_serialize::*;
use ark_std::{rand::RngCore, One, UniformRand, Zero};
use std::ops::{Mul, Sub};
use crate::api::types::E as Q;
use crate::kzg::{UniversalParams, KZG10};
use crate::utils::LagrangePolyHelper;

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct SecretKey<E: Pairing> {
    pub sk: E::ScalarField,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct PublicKey<E: Pairing> {
    pub id: usize,
    pub bls_pk: E::G1,          //BLS pk
    pub sk_li: E::G1,           //hint
    pub sk_li_minus0: E::G1,    //hint
    pub sk_li_by_z: Vec<E::G1>, //hint
    pub sk_li_by_tau: E::G1,    //hint
}

#[derive(Clone)]
pub struct AggregateKey<E: Pairing> {
    pub pk: Vec<PublicKey<E>>,
    pub agg_sk_li_by_z: Vec<E::G1>,
    pub ask: E::G1,
    pub z_g2: E::G2,

    //preprocessed values
    pub h_minus1: E::G2,
    pub e_gh: PairingOutput<E>,
}

impl<E: Pairing> PublicKey<E> {
    pub fn new(
        id: usize,
        bls_pk: E::G1,
        sk_li: E::G1,
        sk_li_minus0: E::G1,
        sk_li_by_z: Vec<E::G1>,
        sk_li_by_tau: E::G1,
    ) -> Self {
        PublicKey {
            id,
            bls_pk,
            sk_li,
            sk_li_minus0,
            sk_li_by_z,
            sk_li_by_tau,
        }
    }
}

impl<E: Pairing> SecretKey<E> {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        SecretKey {
            sk: E::ScalarField::rand(rng),
        }
    }

    pub fn nullify(&mut self) {
        self.sk = E::ScalarField::one()
    }

    pub async fn get_pk(&self, id: usize, params: &UniversalParams<E>, n: usize, lagrange_polys: &Vec<DensePolynomial<E::ScalarField>>) -> PublicKey<E> {
        let domain = Radix2EvaluationDomain::<E::ScalarField>::new(n).unwrap();

        let li: DensePolynomial<<E as Pairing>::ScalarField> = lagrange_polys[id].clone();

        let sk_async = self.sk.clone();

        let bls_pk = tokio::spawn(async move {
            E::G1::generator() * sk_async
        });

        let mut sk_li_by_z_tasks = Vec::new();

        let mut sk_li_by_z: Vec<E::G1> = vec![];
        for j in 0..n {
            let li_async = li.clone();
            let sk_async = self.sk.clone();
            let params_async = params.clone();
            let lagrange_polys_async = lagrange_polys.clone();
            let sk_li_by_z = tokio::spawn(async move {
                let num = if id == j {
                    li_async.mul(&li_async).sub(&li_async)
                } else {
                    //cross-terms
                    //let l_j = lagrange_polys[j].clone();
                    lagrange_polys_async[j].mul(&li_async)
                };

                let f = num.divide_by_vanishing_poly(domain).unwrap().0;
                let sk_times_f = &f * sk_async;

                let com = KZG10::commit_g1(&params_async, &sk_times_f)
                    .expect("commitment failed")
                    .into();

                com
            });
            sk_li_by_z_tasks.push(sk_li_by_z)
        }
        
        let li_async = li.clone();
        let sk_async = self.sk.clone();
        let params_async = params.clone();

        let sk_li_by_tau = tokio::spawn(async move {
            let f: DensePolynomial<<E as Pairing>::ScalarField> = DensePolynomial::from_coefficients_vec(li_async.coeffs[1..].to_vec());
            let sk_times_f = &f * sk_async;
            // let sk_li_by_tau =
            KZG10::commit_g1(&params_async, &sk_times_f)
                .expect("commitment failed")
                .into()
        });

        let mut f = Vec::new();
        f.push(&li * self.sk);
        let params_async = params.clone();
        let f_async = f.clone();

        let sk_li = tokio::spawn(async move {
            KZG10::commit_g1(&params_async, &f_async[0])
                .expect("commitment failed")
                .into()
        });


        let params_async = params.clone();
        let mut f_async = f.clone();

        let sk_li_minus_0 = tokio::spawn(async move {
            f_async[0].coeffs[0] = E::ScalarField::zero();
            // let sk_li_minus0 =
            KZG10::commit_g1(&params_async, &f_async[0])
                .expect("commitment failed")
                .into()
        });

        for task in sk_li_by_z_tasks {
            sk_li_by_z.push(task.await.unwrap());
        }

        PublicKey {
            id,
            bls_pk: bls_pk.await.unwrap(),
            sk_li: sk_li.await.unwrap(),
            sk_li_minus0: sk_li_minus_0.await.unwrap(),
            sk_li_by_z,
            sk_li_by_tau: sk_li_by_tau.await.unwrap(),
        }
    }

    pub fn partial_decryption(&self, gamma_g2: E::G2) -> E::G2 {
        gamma_g2 * self.sk // kind of a bls signature on gamma_g2
    }
}

pub fn get_pk_exp(sk: &SecretKey<Q>, id: usize, _n: usize, lagrange_polys: &LagrangePolyHelper) -> PublicKey<Q> {
    let mut sk_li_by_z = lagrange_polys.li_by_z[id].clone();

    for idx in 0..sk_li_by_z.len() {
        sk_li_by_z[idx] *= sk.sk;
    }

    PublicKey {
        id,
        bls_pk: <Bls12_381 as Pairing>::G1::generator() * sk.sk,
        sk_li: lagrange_polys.li[id] * sk.sk,
        sk_li_minus0: lagrange_polys.li_minus0[id] * sk.sk,
        sk_li_by_z: sk_li_by_z.to_owned(),
        sk_li_by_tau: lagrange_polys.li_by_tau[id] * sk.sk,
    }
}

impl<E: Pairing> AggregateKey<E> {
    pub fn new(pk: Vec<PublicKey<E>>, n: usize, params: &UniversalParams<E>) -> Self {
        let h_minus1 = params.powers_of_h[0] * (-E::ScalarField::one());
        let z_g2 = params.powers_of_h[n] + h_minus1;

        // gather sk_li from all public keys
        let mut ask = E::G1::zero();
        for pki in pk.iter() {
            ask += pki.sk_li;
        }

        let mut agg_sk_li_by_z = vec![];
        for i in 0..n {
            let mut agg_sk_li_by_zi = E::G1::zero();
            for pkj in pk.iter() {
                agg_sk_li_by_zi += pkj.sk_li_by_z[i];
            }
            agg_sk_li_by_z.push(agg_sk_li_by_zi);
        }

        AggregateKey {
            pk,
            agg_sk_li_by_z,
            ask,
            z_g2,
            h_minus1,
            e_gh: E::pairing(params.powers_of_g[0], params.powers_of_h[0]),
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::bls12::Bls12;

    use crate::utils::lagrange_poly;

    use super::*;

    type E = ark_bls12_381::Bls12_381;
    type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

    #[test]
    fn test_setup() {
        let mut rng = ark_std::test_rng();
        let n = 4;
        let params = KZG10::<E, UniPoly381>::setup(n, &mut rng).unwrap();

        let lagrange_polys: Vec<DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>> = (0..n)
            .map(|j| lagrange_poly(n, j))
            .collect();

        let mut sk: Vec<SecretKey<E>> = Vec::new();
        let mut pk: Vec<PublicKey<E>> = Vec::new();

        for i in 0..n {
            sk.push(SecretKey::<E>::new(&mut rng));
            pk.push(sk[i].get_pk(0, &params, n, &lagrange_polys))
        }

        let _ak = AggregateKey::<E>::new(pk, n, &params);
    }
}
