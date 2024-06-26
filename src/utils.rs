#![allow(non_snake_case, unused_variables)]
use std::io::Cursor;

use ark_bls12_381::{G1Affine, G2Affine};
use ark_ff::{FftField, Field};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain,
};
use serde::{Deserialize, Serialize};
use ark_serialize::*;

// 1 at omega^i and 0 elsewhere on domain {omega^i}_{i \in [n]}
pub fn lagrange_poly<F: FftField>(n: usize, i: usize) -> DensePolynomial<F> {
    debug_assert!(i < n);
    //todo: check n is a power of 2
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

#[derive(Serialize, Deserialize)]
pub struct Powers {
    pub G1Powers: Vec<String>,
    pub G2Powers: Vec<String>
}

#[derive(Serialize, Deserialize)]
pub struct Witness {
    pub runningProducts: Vec<String>,
    pub potPubkeys: Vec<String>,
    pub blsSignatures: Vec<String>
}

#[derive(Serialize, Deserialize)]
pub struct Transcript {
    pub numG1Powers: u32,
    pub numG2Powers: u32,
    pub powersOfTau: Powers,
    pub witness: Witness
}

#[derive(Serialize, Deserialize)]
pub struct KZG {
    pub transcripts: Vec<Transcript>
}

pub fn convert_hex_to_g1(g1_powers: &Vec<String>) -> Vec<G1Affine> {
    let mut g1_powers_decompressed = Vec::new();

    let mut j = 0;
    let len = g1_powers.len();
    for i in g1_powers {
        let g1_vec: Vec<u8> = hex::decode(i.clone().split_off(2)).unwrap();
        let mut cur = Cursor::new(g1_vec);
        let g1 = G1Affine::deserialize_compressed(&mut cur).unwrap();
        g1_powers_decompressed.push(g1);
        print!("{}/{}\t\r", j, len);
        // println!("{:#?}", g1);
        j += 1;
    }
    print!("\n");

    g1_powers_decompressed
}

pub fn convert_hex_to_g2(g2_powers: &Vec<String>) -> Vec<G2Affine> {
    let mut g2_powers_decompressed = Vec::new();
    let mut j = 0;
    let len = g2_powers.len();
    for i in g2_powers {
        let g2_powers: Vec<u8> = hex::decode(i.clone().split_off(2)).unwrap();
        let mut cur = Cursor::new(g2_powers);
        let g2 = G2Affine::deserialize_compressed(&mut cur).unwrap();
        g2_powers_decompressed.push(g2);
        print!("{}/{}\t\r", j, len);
        j += 1;
        // println!("{:#?}", g2);
    }
    print!("\n");

    g2_powers_decompressed
}