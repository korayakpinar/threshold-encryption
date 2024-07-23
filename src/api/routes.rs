use actix_protobuf::{ProtoBuf, ProtoBufResponseBuilder};
use actix_web::{HttpRequest, HttpResponse};

use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::*;
use ark_std::Zero;

use rand::Rng;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use block_modes::BlockMode;

use crate::encryption::encrypt;
use crate::setup::{AggregateKey, SecretKey};
use crate::decryption::{agg_dec, part_verify};

use crate::api::types::*;
use crate::utils::lagrange_poly;

use super::deserialize::{deserialize_decrypt_params, deserialize_encrypt, deserialize_gamma_g2, deserialize_pk_req, deserialize_verify_part};


pub async fn encrypt_route(config: HttpRequest, data: ProtoBuf<EncryptRequest>) -> HttpResponse {
    let datum = config.app_data::<Data>().unwrap();
    let kzg_setup = datum.kzg_setup.clone();

    let encrypt_data_res = deserialize_encrypt(data.0);
    if encrypt_data_res.is_none() {
        log::error!("can't deserialize encrypt_data");
        return HttpResponse::BadRequest().finish();
    }
    let encrypt_data = encrypt_data_res.unwrap();

    let mut pks = encrypt_data.pks;

    let mut rng = OsRng;
    
    let lagrange_polys: Vec<DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>> = (0..encrypt_data.n)
        .map(|j| lagrange_poly(encrypt_data.n, j))
        .collect();

    let mut sk_zero: SecretKey<E> = SecretKey::new(&mut rng);
    sk_zero.nullify();
    pks.insert(0, sk_zero.get_pk(0, &kzg_setup, encrypt_data.n, &lagrange_polys));


    let aggregated = AggregateKey::<E>::new(pks, encrypt_data.n, &kzg_setup);
    let ct = encrypt(&aggregated, encrypt_data.t, &kzg_setup);

    let mut hasher = Sha256::new();
    hasher.update(ct.enc_key.to_string().as_bytes());
    let result = hasher.clone().finalize();

    let key = result.as_slice();

    let iv = &mut [0u8; 16];
    rng.fill(iv);

    let cipher_enc_res = Aes256Cbc::new_from_slices(key, iv);
    if cipher_enc_res.is_err() {
        log::error!("can't create Aes256Cbc::new_from_slices(key, iv)");
        HttpResponse::BadRequest().finish();
    }
    let cipher_enc = cipher_enc_res.unwrap();
    
    let enc = cipher_enc.encrypt_vec(&encrypt_data.msg);
    hasher.update(ct.enc_key.to_string().as_bytes());

    let resp = HttpResponse::Ok().protobuf(EncryptResponse::new(enc, ct, iv.to_vec()));
    if resp.is_err() {
        log::error!("can't cast the result to ResultProto");
        return HttpResponse::InternalServerError().finish();
    }
    resp.unwrap()
}

pub async fn decrypt_part_route(config: HttpRequest, data: ProtoBuf<PartDecRequest>) -> HttpResponse {
    let datum = config.app_data::<Data>().unwrap();
    let sk = datum.sk.clone();

    let gamma_g2_res = deserialize_gamma_g2(data.0);
    if gamma_g2_res.is_none() {
        log::error!("can't deserialize gamma_g2");
        return HttpResponse::BadRequest().finish();
    }
    let gamma_g2: G2 = gamma_g2_res.unwrap().gamma_g2;
    
    let val = gamma_g2 * sk.sk;
    
    let mut result = Vec::new();
    let res = val.serialize_compressed(&mut result);
    if res.is_err() {
        log::error!("can't serialize gamma_g2 * sk");
        return HttpResponse::BadRequest().finish();
    }

    let resp = HttpResponse::Ok().protobuf(Response { result });
    if resp.is_err() {
        log::error!("can't cast the result to ResultProto");
        return HttpResponse::InternalServerError().finish();
    }
    resp.unwrap()
}

pub async fn decrypt_route(config: HttpRequest, data: ProtoBuf<DecryptRequest>) -> HttpResponse {
    let datum = config.app_data::<Data>().unwrap();
    let kzg_setup = datum.clone().kzg_setup;

    let params_res = deserialize_decrypt_params(data.0);
    if params_res.is_none() {
        log::error!("can't deserialize decrypt params");
        return HttpResponse::BadRequest().finish();
    }
    let params = params_res.unwrap();

    let mut selector: Vec<bool> = Vec::new();
    let mut partial_decryptions: Vec<G2> = Vec::new();

    selector.push(true);

    let mut rng = OsRng;
    let mut sk_zero: SecretKey<E> = SecretKey::new(&mut rng);
    sk_zero.nullify();
    partial_decryptions.push(sk_zero.partial_decryption(params.gamma_g2));

    for idx in 1..params.n {
        if params.parts.contains_key(&idx) {
            selector.push(true);
            partial_decryptions.push(*params.parts.get(&idx).unwrap());
        } else {
            selector.push(false);
            partial_decryptions.push(G2::zero());
        }
    }

    let mut pks = params.pks;

    let lagrange_polys: Vec<DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>> = (0..params.n)
        .map(|j| lagrange_poly(params.n, j))
        .collect();

    pks.insert(0, sk_zero.get_pk(0, &kzg_setup, params.n, &lagrange_polys));

    //println!("{:#?}, {:#?}, {:#?}, {}, {}", partial_decryptions, partial_decryptions.len(), params.parts.len(), params.t, params.n);

    let aggregated = AggregateKey::<E>::new(pks, params.n, &kzg_setup);
    let key = agg_dec(&partial_decryptions, &params.sa1, &params.sa2, params.t, params.n, &selector, &aggregated, &kzg_setup);

    let mut hasher = Sha256::new();
    hasher.update(key.to_string().as_bytes());
    let result = hasher.finalize();

    let key = result.as_slice();

    let cipher_dec_res = Aes256Cbc::new_from_slices(&key, &params.iv);
    if cipher_dec_res.is_err() {
        log::error!("key or params.decrypt.iv is wrong");
        return HttpResponse::BadRequest().finish();
    }
    let cipher_dec = cipher_dec_res.unwrap();

    let decrypted_res = cipher_dec.decrypt_vec(&params.enc);
    if decrypted_res.is_err() {
        log::error!("failed to decrypt the data, {}", decrypted_res.err().unwrap());
        return HttpResponse::UnavailableForLegalReasons().finish();
    }
    let result = decrypted_res.unwrap();

    let resp = HttpResponse::Ok().protobuf(Response { result });
    if resp.is_err() {
        log::error!("can't cast the result to ResultProto");
        return HttpResponse::InternalServerError().finish();
    }
    resp.unwrap()
}

pub async fn verify_part_route(config: HttpRequest, data: ProtoBuf<VerifyPartRequest>) -> HttpResponse {
    let datum = config.app_data::<Data>().unwrap();
    let kzg_setup = datum.kzg_setup.clone();

    let verify_res = deserialize_verify_part(data.0);
    if verify_res.is_none() {
        log::error!("can't deserialize decrypt params");
        return HttpResponse::InternalServerError().finish();
    }
    let verify = verify_res.unwrap();

    let p = part_verify(verify.gamma_g2, verify.pk, kzg_setup.powers_of_g[0].into(), verify.part_dec);
    if p == true {
        return HttpResponse::Ok().finish();
    }

    HttpResponse::UnavailableForLegalReasons().finish() // LOL
}

pub async fn get_pk_route(config: HttpRequest, data: ProtoBuf<PKRequest>) -> HttpResponse {
    let datum = config.app_data::<Data>().unwrap();
    let sk = &datum.sk;
    let params = &datum.kzg_setup;

    let pk_res = deserialize_pk_req(data.0);
    if pk_res.is_none() {
        log::error!("can't deserialize pk request");
        return HttpResponse::InternalServerError().finish();
    }
    let pk = pk_res.unwrap();

    let lagrange_polys: Vec<DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>> = (0..pk.n)
        .map(|j| lagrange_poly(pk.n, j))
        .collect();

    let pk = sk.get_pk(pk.id, params, pk.n, &lagrange_polys);
    
    let mut result = Vec::new();
    let res = pk.serialize_compressed(&mut result);
    if res.is_err() {
        log::error!("can't serialize public key");
        return HttpResponse::InternalServerError().finish();
    }

    let resp = HttpResponse::Ok().protobuf(Response { result });
    if resp.is_err() {
        log::error!("can't cast the result to ResultProto");
        return HttpResponse::InternalServerError().finish();
    }
    resp.unwrap()
}