use std::io::Cursor;
use std::time;

use actix_protobuf::{ProtoBuf, ProtoBufResponseBuilder};
use actix_web::{HttpRequest, HttpResponse};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::log2;
use rand::Rng;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use block_modes::BlockMode;

use crate::encryption::encrypt;
use crate::setup::{get_pk_exp, AggregateKey, SecretKey};

use crate::api::types::*;
use crate::utils::LagrangePoly;

pub async fn encrypt_route(config: HttpRequest, data: ProtoBuf<EncryptRequest>) -> HttpResponse {
    unsafe { libc::malloc_trim(0); }

    let ti = time::Instant::now();
    let datum = config.app_data::<Data>().unwrap();
    let kzg_setup = &datum.kzg_setup;

    let encrypt_data_res = data.0.deserialize();
    if encrypt_data_res.is_none() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't deserialize encrypt_data");
        return HttpResponse::BadRequest().finish();
    }
    let encrypt_data = encrypt_data_res.unwrap();

    let mut pks = encrypt_data.pks;

    let log2_n = log2(encrypt_data.n) as usize - 1;
    let req = Poly { log2_n, idx: 0 };
    
    let mut wr = Vec::new();
    let serialize_result = req.serialize_compressed(&mut wr);
    if serialize_result.is_err() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't serialize data!");
        return HttpResponse::InternalServerError().finish();
    }
    
    let mut rng = OsRng;
    let mut sk_zero: SecretKey<E> = SecretKey::new(&mut rng);
    sk_zero.nullify();

    let client = &datum.client;
    let resp = client.post(&datum.mempool).body(wr).send().await;
    if resp.is_err() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't reach internal api!");
        return HttpResponse::InternalServerError().finish();
    }
    let bytes = resp.unwrap().bytes().await;
    if bytes.is_err() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't read bytes from internal api response!");
        return HttpResponse::InternalServerError().finish();
    }
    let cur = Cursor::new(bytes.unwrap());
    let lagrange_poly = LagrangePoly::deserialize_compressed(cur);
    if lagrange_poly.is_err() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't deserialize bytes from internal api response!");
        return HttpResponse::InternalServerError().finish();
    }

    pks.insert(0, get_pk_exp(&sk_zero, 0, &lagrange_poly.unwrap()));

    let aggregated = AggregateKey::<E>::new(pks.clone(), pks.len(), &kzg_setup);
    let ct = encrypt(&aggregated, encrypt_data.t, &kzg_setup);

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
    drop(aggregated);
    drop(sk_zero);
    drop(encrypt_data.msg);
    drop(req);

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