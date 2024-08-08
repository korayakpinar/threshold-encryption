use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_ff::{FftField, Field};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain,
};
use ark_std::Zero;
use std::{ops::{Mul, Sub}, time};

use crate::{api::types::{E, G2}, kzg::{UniversalParams, KZG10}};

// 1 at omega^i and 0 elsewhere on domain {omega^i}_{i \in [n]}
pub fn lagrange_poly<F: FftField>(n: usize, i: usize) -> DensePolynomial<F> {
    debug_assert!(i < n);
    debug_assert!((n != 0) && ((n & (n - 1)) == 0));
    let mut evals = vec![];
    for j in 0..n {
        let l_of_x: u64 = if i == j { 1 } else { 0 };
        evals.push(F::from(l_of_x));
    }

    //powers of nth root of unity
    let domain = Radix2EvaluationDomain::<F>::new(n).unwrap();
    let eval_form = Evaluations::from_vec_and_domain(evals, domain);
    //interpolated polynomial over the n points
    eval_form.interpolate()
}

/// interpolates a polynomial when all evaluations except at points[0] are zero
/// todo: check that multiplication is fast as one polynomial is shorter
pub fn interp_mostly_zero<F: Field>(eval: F, points: &Vec<F>) -> DensePolynomial<F> {
    if points.is_empty() {
        // threshold=n
        return DensePolynomial::from_coefficients_vec(vec![F::one()]);
    }

    let mut interp = DensePolynomial::from_coefficients_vec(vec![F::one()]);
    for &point in &points[1..] {
        interp = interp.naive_mul(&DensePolynomial::from_coefficients_vec(vec![
            -point,
            F::one(),
        ]));
    }

    let scale = interp.evaluate(&points[0]);
    interp = &interp * (eval / scale);

    interp
}


pub struct IsValidHelper {
    pub li: G2,
    pub li_minus0: G2,
    pub li_by_tau: G2,
    pub li_by_z: Vec<G2>
}

impl IsValidHelper {
    pub fn new(n: usize, lagrange_polys: &Vec<DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>>, params: &UniversalParams<E>) -> Vec<Self> {
        let domain = Radix2EvaluationDomain::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(n).unwrap();

        let mut self_vec: Vec<Self> = Vec::new();

        for id in 0..n {
            let ti = time::Instant::now();
            let li = &lagrange_polys[id];

            let mut li_by_z = vec![];
            for j in 0..n {
                let num = if id == j {
                    li.mul(li).sub(li)
                } else {
                    //cross-terms
                    //let l_j = lagrange_polys[j].clone();
                    lagrange_polys[j].mul(li)
                };

                let f = num.divide_by_vanishing_poly(domain).unwrap().0;

                let com = KZG10::commit_g2(params, &f)
                    .expect("commitment failed")
                    .into();

                li_by_z.push(com);
            }

            let f = DensePolynomial::from_coefficients_vec(li.coeffs[1..].to_vec());
            let li_by_tau = KZG10::commit_g2(params, &f)
                .expect("commitment failed")
                .into();

            let mut f = li.to_owned();
            let li = KZG10::commit_g2(params, &f)
                .expect("commitment failed")
                .into();

            f.coeffs[0] = <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::zero();
            let li_minus0 = KZG10::commit_g2(params, &f)
                .expect("commitment failed")
                .into();
            
            self_vec.push(
                Self {
                    li,
                    li_by_tau,
                    li_by_z,
                    li_minus0
                }
            );
            println!("{}: {:#?} elapsed", id, ti.elapsed());
        }

        self_vec
    }
}