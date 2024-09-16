use std::{fs::File, io::{Cursor, Read}};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;
use silent_threshold::{api::types::E, kzg::UniversalParams, setup::{get_pk_exp, AggregateKey, PublicKey, SecretKey}, utils::{LagrangePoly, LagrangePolyHelper}};


fn load_lagrange_helper(n: usize) -> LagrangePolyHelper {
    let mut file = File::open(format!("./lagrangehelpers/{}", n)).unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    let cur = Cursor::new(contents);
    println!("Loading lagrange helper...");
    LagrangePolyHelper::deserialize_compressed(cur).unwrap()
}

fn load_universal_params() -> UniversalParams<E> {
    let mut file = File::open("transcript-512").unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    let cur = Cursor::new(contents);
    println!("Loading universal params...");
    UniversalParams::deserialize_compressed(cur).unwrap()
}

fn load_aggregated_key() -> AggregateKey<E> {
    let mut file = File::open("./aggregatedkey").unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    let cur = Cursor::new(contents);
    println!("Loading aggregated key...");
    AggregateKey::<E>::deserialize_compressed(cur).unwrap()
}

fn main() {
    let mut file = File::open("./aggregatedkey").unwrap();
    let mut v = Vec::new();
    file.read_to_end(&mut v).unwrap();

    let mut pks = Vec::new();

    let lagrange_helper = load_lagrange_helper(512);
    let params = load_universal_params();

    let mut rng = OsRng;
    let mut sk = SecretKey::<E>::new(&mut rng);
    sk.nullify();

    let lagrange_poly = LagrangePoly::new(0, &lagrange_helper);
    pks.push(get_pk_exp(&sk, 0, &lagrange_poly));

    for i in 1..512 {
        println!("{}", i);
        let mut file = File::open(format!("./keys/{}-pk", i)).unwrap();
        let mut v = Vec::new();
        file.read_to_end(&mut v).unwrap();

        let cur = Cursor::new(v);
        let pk = PublicKey::<E>::deserialize_uncompressed_unchecked(cur).unwrap();
        pks.push(pk);
    }

    let agg_created = AggregateKey::<E>::new(pks, 512, &params);
    let agg_written = load_aggregated_key();

    let mut z = Vec::new();
    let mut z_prime = Vec::new();

    agg_created.serialize_compressed(&mut z).unwrap();
    agg_written.serialize_compressed(&mut z_prime).unwrap();

    println!("{}", z == z_prime);

}