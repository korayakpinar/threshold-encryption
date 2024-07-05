use actix_protobuf::{ProtoBuf, ProtoBufResponseBuilder};
use actix_web::{HttpRequest, HttpResponse};

use ark_serialize::*;

use sha2::{Sha256, Digest};
use block_modes::BlockMode;

use crate::setup::AggregateKey;
use crate::decryption::{agg_dec, part_verify};

use crate::api::types::*;

use super::deserialize::{deserialize_decrypt_params, deserialize_gamma_g2, deserialize_verify_part};


pub async fn decrypt_part(config: HttpRequest, data: ProtoBuf<GammaG2Proto>) -> HttpResponse {
    let datum = config.app_data::<Data>().unwrap();
    let sk = datum.clone().sk;

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

    let resp = HttpResponse::Ok().protobuf(ResultProto { result });
    if resp.is_err() {
        log::error!("can't cast the result to ResultProto");
        return HttpResponse::InternalServerError().finish();
    }
    resp.unwrap()
}

pub async fn decrypt(config: HttpRequest, data: ProtoBuf<DecryptParamsProto>) -> HttpResponse {
    let datum = config.app_data::<Data>().unwrap();
    let kzg_setup = datum.clone().kzg_setup;
    log::info!("params_res");
    let params_res = deserialize_decrypt_params(data.0);
    if params_res.is_none() {
        log::error!("can't deserialize decrypt params");
        return HttpResponse::BadRequest().finish();
    }
    let params = params_res.unwrap();

    let mut selector: Vec<bool> = Vec::new();
    for _ in 0..params.t + 1 {
        selector.push(true);
    }
    for _ in params.t + 1..params.n {
        selector.push(false);
    }
    
    let aggregated = AggregateKey::<E>::new(params.pks.clone(), &kzg_setup);

    let key = agg_dec(&params.parts, &params.sa1, &params.sa2, params.t, &selector, &aggregated, &kzg_setup);

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
        log::error!("failed to decrypt the data");
        return HttpResponse::BadRequest().finish();
    }
    let result = decrypted_res.unwrap();

    let resp = HttpResponse::Ok().protobuf(ResultProto { result });
    if resp.is_err() {
        log::error!("can't cast the result to ResultProto");
        return HttpResponse::InternalServerError().finish();
    }
    resp.unwrap()
}

pub async fn verify_decryption_part(config: HttpRequest, data: ProtoBuf<VerifyPartProto>) -> HttpResponse {
    let datum = config.app_data::<Data>().unwrap();
    let kzg_setup = datum.clone().kzg_setup;

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