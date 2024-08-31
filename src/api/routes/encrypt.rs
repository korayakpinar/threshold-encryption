#![allow(unused_imports)]
use std::io::Cursor;
use std::time;

use actix_protobuf::ProtoBufResponseBuilder;
use actix_web::{web, HttpRequest, HttpResponse};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::log2;
use prost::Message;
use rand::Rng;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use block_modes::BlockMode;

use crate::encryption::encrypt;
use crate::setup::{get_pk_exp, AggregateKey, SecretKey};

use crate::api::types::*;
use crate::utils::LagrangePoly;

pub async fn encrypt_route(config: HttpRequest, data: web::Payload) -> HttpResponse {
    unsafe { libc::malloc_trim(0); }

    let ti = time::Instant::now();
    let bytes_tmp = data.to_bytes().await;
    if bytes_tmp.is_err() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't read bytes");
        return HttpResponse::BadRequest().finish();
    }
    let bytes = bytes_tmp.unwrap();


    let data_tmp = EncryptRequest::decode(bytes);
    if data_tmp.is_err() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't decode bytes to encrypt request");
        return HttpResponse::BadRequest().finish();
    }
    let data = data_tmp.unwrap();

    let datum = config.app_data::<Data>().unwrap();
    let kzg_setup = &datum.kzg_setup;

    let encrypt_data_res = data.deserialize();
    if encrypt_data_res.is_none() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't deserialize encrypt_data");
        return HttpResponse::BadRequest().finish();
    }
    let encrypt_data = encrypt_data_res.unwrap();

    let ct = encrypt(&datum.aggregated, encrypt_data.t, &kzg_setup);

    let mut rng = OsRng;
    let mut hasher = Sha256::new();
    hasher.update(ct.enc_key.to_string().as_bytes());
    let result = hasher.clone().finalize();

    let key = result.as_slice();

    let iv = &mut [0u8; 16];
    rng.fill(iv);

    let cipher_enc_res = Aes256Cbc::new_from_slices(key, iv);
    if cipher_enc_res.is_err() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't create Aes256Cbc::new_from_slices(key, iv)");
        HttpResponse::BadRequest().finish();
    }
    let cipher_enc = cipher_enc_res.unwrap();
    
    let enc = cipher_enc.encrypt_vec(&encrypt_data.msg);
    hasher.update(ct.enc_key.to_string().as_bytes());

    drop(hasher);
    /* drop(aggregated);
    drop(sk_zero); */
    drop(encrypt_data.msg);
    /* drop(req); */

    let resp = HttpResponse::Ok().protobuf(EncryptResponse::new(enc, ct, iv.to_vec()));
    if resp.is_err() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't cast the result to ResultProto");
        return HttpResponse::InternalServerError().finish();
    }
    log::info!("elapsed on encrypt: {:#?}", ti.elapsed());
    unsafe { libc::malloc_trim(0); }
    resp.unwrap()
}