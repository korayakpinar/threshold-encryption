use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_ff::{FftField, Field};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::Zero;
use std::{ops::{Mul, Sub}, sync::Once, time};

use libc::{self, malloc_zone_t};
use crate::{api::types::{E, G1, G2}, kzg::{UniversalParams, KZG10}, setup::SecretKey};

#[cfg(target_os = "macos")]
extern "C" {
    fn malloc_zone_pressure_relief(zone: *mut malloc_zone_t, goal: usize);
}

#[cfg(target_os = "macos")]
pub unsafe fn malloc_trim(n: usize) {
    let zone = libc::malloc_default_zone();
    malloc_zone_pressure_relief(zone, n);
} 

#[cfg(target_os = "linux")]
pub unsafe fn malloc_trim(n: usize) {
    libc::malloc_trim(n);
} 

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

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct IsValidPoly {
    pub li: G2,
    pub li_minus0: G2,
    pub li_by_tau: G2,
    pub li_by_z: Vec<G2>,
}

impl IsValidPoly {
    pub fn new(idx: usize, polys: &IsValidHelper) -> Self {
        Self {
            li: polys.li[idx],
            li_minus0: polys.li_minus0[idx],
            li_by_tau: polys.li_by_tau[idx],
            li_by_z: polys.li_by_z[idx].clone() 
        }

    }
}


#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct IsValidHelper {
    pub li: Vec<G2>,
    pub li_minus0: Vec<G2>,
    pub li_by_tau: Vec<G2>,
    pub li_by_z: Vec<Vec<G2>>
}

impl IsValidHelper {
    pub async fn new(n: usize) -> Self {
        let domain = Radix2EvaluationDomain::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(n).unwrap();

        let mut tasks = Vec::new();
        let mut li_by_z_times_li_tasks = Vec::new();

        for id in 0..n {
            let li_task = tokio::spawn(async move {
                let li: G2 = KZG10::commit_g2(&get_kzg_setup(), &get_lagrange_polys()[id].to_owned())
                    .expect("commitment failed")
                    .into();
                
                li
            });
            tasks.push(li_task);

            let li_minus0_task = tokio::spawn(async move {
                let mut f = get_lagrange_polys()[id].to_owned();
                f.coeffs[0] = <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::zero();
                let li_minus0 = KZG10::commit_g2(&get_kzg_setup(), &f)
                    .expect("commitment failed")
                    .into();

                li_minus0
            });
            tasks.push(li_minus0_task);

            let li_by_tau_task = tokio::spawn(async move {
                let f: DensePolynomial<<E as Pairing>::ScalarField> = DensePolynomial::from_coefficients_vec(get_lagrange_polys()[id].coeffs[1..].to_vec());
                let li_by_tau_task = KZG10::commit_g2(&get_kzg_setup(), &f)
                    .expect("commitment failed")
                    .into();

                li_by_tau_task
            });
            tasks.push(li_by_tau_task);

            // let c = sk.clone();
            for j in 0..n {
                if j == id {
                    let li_by_z_task = tokio::spawn(async move {
                        let li = &get_lagrange_polys()[id];
                        let l = li.mul(li).sub(li);
        
                        let f = l.divide_by_vanishing_poly(domain).unwrap().0;
        
                        let li_by_z = KZG10::commit_g2(&get_kzg_setup(), &f)
                            .expect("commitment failed")
                            .into();
        
                        li_by_z
                    });
                    li_by_z_times_li_tasks.push(li_by_z_task);
                    continue;
                }

                let li_by_z_times_li_task = tokio::spawn(async move {
                    let li = &get_lagrange_polys()[id];
                    let li_j = &get_lagrange_polys()[j];
                    let l = li_j.mul(li);

                    let f = l.divide_by_vanishing_poly(domain).unwrap().0;

                    let li_by_z_times_li = KZG10::commit_g2(&get_kzg_setup(), &f)
                        .expect("commitment failed")
                        .into();

                    li_by_z_times_li
                });
                li_by_z_times_li_tasks.push(li_by_z_times_li_task)
            }
        }

        let mut ret = Self {
                                                    li: Vec::new(),
                                                    li_minus0: Vec::new(),
                                                    li_by_tau: Vec::new(),
                                                    li_by_z: Vec::new(),
                                            };

        for (idx, task) in tasks.into_iter().enumerate() {
            let t = time::Instant::now();
            match idx % 3 {
                0 => ret.li.push(task.await.unwrap()),
                1 => ret.li_minus0.push(task.await.unwrap()),
                2 => ret.li_by_tau.push(task.await.unwrap()),
                // 3 => li_by_z.push(task.await.unwrap()),
                //4 => ret.li_by_z_times_li.push(task.await.unwrap()* sk.sk),
                _ => unreachable!()
            }
            println!("tasks: {} - {:#?}", idx, t.elapsed());
        }

        let mut li_by_z_times_li = Vec::new();
        let mut tmp = Vec::new();
        for (idx, task) in li_by_z_times_li_tasks.into_iter().enumerate() {
            let t = time::Instant::now();
            if idx % n == 0 && idx != 0 {
                li_by_z_times_li.push(tmp.to_owned());
                tmp.clear()
            }
            tmp.push(task.await.unwrap());
            println!("tasks_z: {} - {:#?}", idx, t.elapsed());
        }
        li_by_z_times_li.push(tmp.to_owned());
        ret.li_by_z = li_by_z_times_li;
        
        ret
    }
}

static mut LAGRANGE_POLYS: Option<&'static [DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>]> = None;
static LAGRANGE_INIT: Once = Once::new();

static mut KZG_SETUP: Option<UniversalParams<E>> = None;
static KZG_INIT: Once = Once::new();

fn initialize_lagrange_polys(n: usize) {
    let polys: Vec<DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>> = (0..n)
        .map(|j| lagrange_poly(n, j))
        .collect();
    unsafe {
        LAGRANGE_POLYS = Some(Box::leak(polys.into_boxed_slice()));
    }
}

fn get_lagrange_polys() -> &'static [DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>] {
    unsafe {
        LAGRANGE_POLYS.expect("LAGRANGE_POLYS has not been initialized")
    }
}

fn initialize_kzg_setup(kzg_setup: UniversalParams<E>) {
    unsafe {
        KZG_SETUP = Some(kzg_setup);
    }
}

fn get_kzg_setup() -> &'static UniversalParams<E> {
    unsafe {
        KZG_SETUP.as_ref().expect("KZG_SETUP has not been initialized")
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct LagrangePoly {
    pub li: G1,
    pub li_minus0: G1,
    pub li_by_tau: G1,
    pub li_by_z: Vec<G1>,
}

impl LagrangePoly {
    pub fn new(idx: usize, polys: &LagrangePolyHelper) -> Self {
        Self {
            li: polys.li[idx],
            li_minus0: polys.li_minus0[idx],
            li_by_tau: polys.li_by_tau[idx],
            li_by_z: polys.li_by_z[idx].clone() 
        }

    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct LagrangePolyHelper {
    pub li: Vec<G1>,
    pub li_minus0: Vec<G1>,
    pub li_by_tau: Vec<G1>,
    pub li_by_z: Vec<Vec<G1>>,
}

impl LagrangePolyHelper {
    pub async fn new(_sk: &SecretKey<E>, n: usize, params: &UniversalParams<E>) -> Self {
        let domain = Radix2EvaluationDomain::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(n).unwrap();

        KZG_INIT.call_once(|| {
            initialize_kzg_setup(params.to_owned());
        });

        LAGRANGE_INIT.call_once(|| {
            initialize_lagrange_polys(n);
        });

        let mut tasks = Vec::new();
        let mut li_by_z_times_li_tasks = Vec::new();

        for id in 0..n {
            let li_task = tokio::spawn(async move {
                let li: G1 = KZG10::commit_g1(&get_kzg_setup(), &get_lagrange_polys()[id].to_owned())
                    .expect("commitment failed")
                    .into();
                
                li
            });
            tasks.push(li_task);

            let li_minus0_task = tokio::spawn(async move {
                let mut f = get_lagrange_polys()[id].to_owned();
                f.coeffs[0] = <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField::zero();
                let li_minus0 = KZG10::commit_g1(&get_kzg_setup(), &f)
                    .expect("commitment failed")
                    .into();

                li_minus0
            });
            tasks.push(li_minus0_task);

            let li_by_tau_task = tokio::spawn(async move {
                let f: DensePolynomial<<E as Pairing>::ScalarField> = DensePolynomial::from_coefficients_vec(get_lagrange_polys()[id].coeffs[1..].to_vec());
                let li_by_tau_task = KZG10::commit_g1(&get_kzg_setup(), &f)
                    .expect("commitment failed")
                    .into();

                li_by_tau_task
            });
            tasks.push(li_by_tau_task);

            // let c = sk.clone();
            for j in id..n {
                if j == id {
                    let li_by_z_task = tokio::spawn(async move {
                        let li = &get_lagrange_polys()[id];
                        let l = li.mul(li).sub(li);
        
                        let f = l.divide_by_vanishing_poly(domain).unwrap().0;
        
                        let li_by_z = KZG10::commit_g1(&get_kzg_setup(), &f)
                            .expect("commitment failed")
                            .into();
        
                        li_by_z
                    });
                    li_by_z_times_li_tasks.push(li_by_z_task);
                    continue;
                }

                let li_by_z_times_li_task = tokio::spawn(async move {
                    let li = &get_lagrange_polys()[id];
                    let li_j = &get_lagrange_polys()[j];
                    let l = li_j.mul(li);

                    let f = l.divide_by_vanishing_poly(domain).unwrap().0;

                    let li_by_z_times_li = KZG10::commit_g1(&get_kzg_setup(), &f)
                        .expect("commitment failed")
                        .into();

                    li_by_z_times_li
                });
                li_by_z_times_li_tasks.push(li_by_z_times_li_task)
            }
        }

        let mut ret = Self {
                                                    li: Vec::new(),
                                                    li_minus0: Vec::new(),
                                                    li_by_tau: Vec::new(),
                                                    li_by_z: Vec::new(),
                                            };

        for (idx, task) in tasks.into_iter().enumerate() {
            let t = time::Instant::now();
            match idx % 3 {
                0 => ret.li.push(task.await.unwrap()),
                1 => ret.li_minus0.push(task.await.unwrap()),
                2 => ret.li_by_tau.push(task.await.unwrap()),
                // 3 => li_by_z.push(task.await.unwrap()),
                //4 => ret.li_by_z_times_li.push(task.await.unwrap()* sk.sk),
                _ => unreachable!()
            }
            println!("tasks: {} - {:#?}", idx, t.elapsed());
        }

        let mut resolved: Vec<G1> = Vec::new();
        for task in li_by_z_times_li_tasks {
            resolved.push(task.await.unwrap());
        }

        let mut li_by_z_times_li: Vec<Vec<G1>> = vec![vec![G1::zero(); n]; n];

        let mut resolved_index = 0;

        for i in 0..n {
            for j in i..n {
                li_by_z_times_li[i][j] = resolved[resolved_index];
                if j != i {
                    li_by_z_times_li[j][i] = resolved[resolved_index];
                }

                resolved_index += 1;
            }
        }

        ret.li_by_z = li_by_z_times_li;
        
        ret
    }
}