#![allow(unused_imports)]
use std::io::Cursor;
use std::time;

use actix_protobuf::ProtoBufResponseBuilder;
use actix_web::{web, HttpRequest, HttpResponse};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{log2, Zero};

use prost::Message;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use block_modes::BlockMode;

use crate::setup::{get_pk_exp, AggregateKey, SecretKey};
use crate::decryption::agg_dec;

use crate::api::types::*;
use crate::utils::{malloc_trim, LagrangePoly};

pub async fn decrypt_route(config: HttpRequest, data: web::Payload) -> HttpResponse {
    unsafe { malloc_trim(0); }

    let ti = time::Instant::now();
    let bytes_tmp = data.to_bytes().await;
    if bytes_tmp.is_err() {
        unsafe { malloc_trim(0); }
        log::error!("can't read bytes");
        return HttpResponse::BadRequest().finish();
    }
    let bytes = bytes_tmp.unwrap();


    let data_tmp = DecryptRequest::decode(bytes);
    if data_tmp.is_err() {
        unsafe { malloc_trim(0); }
        log::error!("can't decode bytes to decrypt request");
        return HttpResponse::BadRequest().finish();
    }
    let data = data_tmp.unwrap();

    let datum = config.app_data::<Data>().unwrap();
    let kzg_setup = &datum.kzg_setup;

    let params_res = data.deserialize();
    if params_res.is_none() {
        unsafe { malloc_trim(0); }
        log::error!("can't deserialize decrypt params");
        return HttpResponse::BadRequest().finish();
    }
    let params = params_res.unwrap();

    let mut selector: Vec<bool> = Vec::new();
    selector.push(true);    
    
    let mut rng = OsRng;

    let mut sk_zero: SecretKey<E> = SecretKey::new(&mut rng);
    sk_zero.nullify();

    let mut partial_decryptions: Vec<G2> = Vec::new();
    partial_decryptions.push(sk_zero.partial_decryption(params.gamma_g2));

    for idx in 0..params.n {
        if params.parts.contains_key(&idx) {
            selector.push(true);
            partial_decryptions.push(*params.parts.get(&idx).unwrap());
        } else {
            selector.push(false);
            partial_decryptions.push(G2::zero());
        }
    }

    let key = agg_dec(&partial_decryptions, &params.sa1, &params.sa2, params.t, params.n, &selector, &datum.aggregated, &kzg_setup).await;

    let mut hasher = Sha256::new();
    hasher.update(key.to_string().as_bytes());
    let result = hasher.finalize();

    let key = result.as_slice();

    let cipher_dec_res = Aes256Cbc::new_from_slices(&key, &params.iv);
    if cipher_dec_res.is_err() {
        unsafe { malloc_trim(0); }
        log::error!("key or params.decrypt.iv is wrong");
        return HttpResponse::BadRequest().finish();
    }
    let cipher_dec = cipher_dec_res.unwrap();

    let decrypted_res = cipher_dec.decrypt_vec(&params.enc);
    if decrypted_res.is_err() {
        unsafe { malloc_trim(0); }
        log::error!("failed to decrypt the data, {}", decrypted_res.err().unwrap());
        return HttpResponse::UnavailableForLegalReasons().finish();
    }
    let result = decrypted_res.unwrap();

    drop(sk_zero);
    drop(selector);
    drop(partial_decryptions);
    drop(params.enc);
    drop(params.iv);
    drop(params.parts);

    let resp = HttpResponse::Ok().protobuf(Response { result });
    if resp.is_err() {
        unsafe { malloc_trim(0); }
        log::error!("can't cast the result to ResultProto");
        return HttpResponse::InternalServerError().finish();
    }
    log::info!("elapsed on decrypt: {:#?}", ti.elapsed());
    unsafe { malloc_trim(0); }
    resp.unwrap()
}