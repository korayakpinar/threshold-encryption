use core::panic;

use ark_poly::univariate::DensePolynomial;
use clap::Parser;

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use rand::rngs::OsRng;
use silent_threshold::kzg::{UniversalParams, KZG10};

type E = Bls12_381;
type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

use std::fs::File;
use ark_serialize::*;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Comittee size
    #[arg(short)]
    n: usize,
}

fn main() {
    let args = Args::parse();

    if args.n != 0 && (args.n & (args.n - 1)) != 0 {
        panic!("n should be a power of two");
    }

    let mut rng = OsRng;
    let kzg_setup: UniversalParams<E> = KZG10::<E, UniPoly381>::setup(args.n, &mut rng).unwrap();

    let mut file = File::create(format!("transcript-{}", args.n)).expect("Can't open the file!");
    let mut wr = Vec::new();
    kzg_setup.clone().serialize_compressed(&mut wr).unwrap();
    file.write_all(&wr).expect("Can't write to the file!");

    println!("powers_of_g: {}, powers_of_h: {}", kzg_setup.powers_of_g.len(), kzg_setup.powers_of_h.len());
}