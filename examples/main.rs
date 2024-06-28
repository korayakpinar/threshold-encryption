use actix_web::{middleware, web, App, HttpRequest, HttpResponse, HttpServer};
use ark_ec::pairing::Pairing;

use ark_bls12_381::{Bls12_381, G2Affine};
use ark_serialize::*;

use sha2::{Sha256, Digest};
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

use std;
use std::fs::File;
use std::io::Cursor;

use hex;
use serde_json;

use silent_threshold::setup::{AggregateKey, DecryptParams, PublicKey, SecretKey};
use silent_threshold::kzg::UniversalParams;
use silent_threshold::decryption::{agg_dec, part_verify};
use silent_threshold::utils::{KZG, convert_hex_to_g1, convert_hex_to_g2};

type E = Bls12_381;
type G2 = <E as Pairing>::G2;
type G1 = <E as Pairing>::G1;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

async fn decrypt_part(config: HttpRequest, data: String) -> HttpResponse {
    let datum = config.app_data::<Data>().unwrap();
    let sk = datum.clone().sk;

    let bytes_res = hex::decode(data);
    if bytes_res.is_err() {
        log::error!("can't decode hex");
        return HttpResponse::BadRequest().finish();
    }
    let bytes = bytes_res.unwrap();

    let gamma_g2_res = G2Affine::deserialize_compressed(bytes.as_slice());
    if gamma_g2_res.is_err() {
        log::error!("can't deserialize gamma_g2");
        return HttpResponse::BadRequest().finish();
    }
    let gamma_g2: G2 = gamma_g2_res.unwrap().into();
    
    let val = gamma_g2 * sk.sk;
    
    let mut result = Vec::new();
    let res = val.serialize_compressed(&mut result);
    if res.is_err() {
        log::error!("can't serialize gamma_g2 * sk");
        return HttpResponse::BadRequest().finish();
    }
    HttpResponse::Ok().body(hex::encode(result))
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct Parameters {
    decrypt: DecryptParams,
    pks: Vec<PublicKey<E>>,
    parts: Vec<G2>
}

async fn decrypt(config: HttpRequest, data: String) -> HttpResponse {
    let datum = config.app_data::<Data>().unwrap();
    let kzg_setup = datum.clone().kzg_setup;

    let bytes_res = hex::decode(data);
    if bytes_res.is_err() {
        log::error!("can't decode hex");
        return HttpResponse::BadRequest().finish();
    }
    let bytes = bytes_res.unwrap();

    let mut cur = Cursor::new(&bytes);
    let params_res = Parameters::deserialize_compressed(&mut cur);
    if params_res.is_err() {
        log::error!("can't deserialize data with Parameters");
        return HttpResponse::BadRequest().finish();
    }
    let params = params_res.unwrap();

    let mut selector: Vec<bool> = Vec::new();
    for _ in 0..params.decrypt.t + 1 {
        selector.push(true);
    }
    for _ in params.decrypt.t + 1..params.decrypt.n {
        selector.push(false);
    }
    
    let aggregated = AggregateKey::<E>::new(params.pks.clone(), &kzg_setup);

    let key = agg_dec(&params.parts, &params.decrypt.sa1, &params.decrypt.sa2, params.decrypt.t, &selector, &aggregated, &kzg_setup);

    let mut hasher = Sha256::new();
    hasher.update(key.to_string().as_bytes());
    let result = hasher.finalize();

    let key = result.as_slice();

    let cipher_dec_res = Aes256Cbc::new_from_slices(&key, &params.decrypt.iv);
    if cipher_dec_res.is_err() {
        log::error!("key or params.decrypt.iv is wrong");
        return HttpResponse::BadRequest().finish();
    }
    let cipher_dec = cipher_dec_res.unwrap();

    let decrypted_res = cipher_dec.decrypt_vec(&params.decrypt.enc);
    if decrypted_res.is_err() {
        log::error!("failed to decrypt the data");
        return HttpResponse::BadRequest().finish();
    }
    let decrypted = decrypted_res.unwrap();

    HttpResponse::Ok().body(hex::encode(decrypted))
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct VerifyPart {
    gamma_g2: G2,
    pk: PublicKey<E>,
    g1: G1,
    part_dec: G2
}

async fn verify_decryption_part(data: String) -> HttpResponse {
    // println!("{}", data);

    let bytes_res = hex::decode(data);
    if bytes_res.is_err() {
        log::error!("can't decode hex");
        return HttpResponse::BadRequest().finish();
    }
    let bytes = bytes_res.unwrap();

    let mut cur = Cursor::new(&bytes);

    let verify_res = VerifyPart::deserialize_compressed(&mut cur);
    if !verify_res.is_err() {
        log::error!("can't deserialize data with VerifyPart");
        return HttpResponse::BadRequest().finish();
    }
    let verify = verify_res.unwrap();

    let p = part_verify(verify.gamma_g2, verify.pk, verify.g1, verify.part_dec);
    if p == true {
        return HttpResponse::Ok().finish();
    }

    HttpResponse::UnavailableForLegalReasons().finish() // LOL
}

#[derive(Clone)]
struct Data {
    kzg_setup: UniversalParams<E>,
    sk: SecretKey<E>
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    
    let mut file = File::open("transcript.json").expect("can't open transcript.json");

    let mut contents: String = String::new();
    file.read_to_string(&mut contents).expect("can't read transcript.json to a string");

    log::info!("size: {}", contents.len());
    let json: KZG = serde_json::from_str::<KZG>(&mut contents).expect("can't deserialize data from transcript.json").into();
    log::info!("numG1Powers: {}", json.transcripts[3].numG1Powers);

    let powers_of_g = convert_hex_to_g1(&json.transcripts[3].powersOfTau.G1Powers);
    let powers_of_h = convert_hex_to_g2(&json.transcripts[3].powersOfTau.G2Powers);

    let kzg_setup: UniversalParams<E> = UniversalParams { powers_of_g, powers_of_h };

    let mut file = File::open("~/.sk").expect("Can't open the file!");
    let mut contents: String = String::new();
    file.read_to_string(&mut contents).expect("Can't read the file!");
    let mut bytes: Vec<u8> = hex::decode(&contents).expect("Can't decode hex"); // TODO: Fix this
    let mut cursor = Cursor::new(&mut bytes);
    let deserialized: <E as Pairing>::ScalarField = CanonicalDeserialize::deserialize_compressed(&mut cursor).expect("Unable to deserialize the data!");
    let sk: SecretKey<E> = SecretKey { sk: deserialized };

    let data = web::Data::new(Data {kzg_setup, sk});

    log::info!("starting HTTP server at http://localhost:8080");
    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web::JsonConfig::default().limit(240000)) // <- limit size of the payload (global configuration)
            .app_data(Data::clone(&data))
            .service(web::resource("/partdec").route(web::post().to(decrypt_part)))
            .service(web::resource("/decrypt").route(web::post().to(decrypt)))
            .service(web::resource("/verifydec").route(web::post().to(verify_decryption_part)))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}