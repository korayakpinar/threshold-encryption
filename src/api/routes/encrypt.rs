use actix_protobuf::{ProtoBuf, ProtoBufResponseBuilder};
use actix_web::{HttpRequest, HttpResponse};

use ark_std::log2;
use rand::Rng;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use block_modes::BlockMode;

use crate::encryption::encrypt;
use crate::setup::{get_pk_exp, AggregateKey, SecretKey};

use crate::api::types::*;

pub async fn encrypt_route(config: HttpRequest, data: ProtoBuf<EncryptRequest>) -> HttpResponse {
    let datum = config.app_data::<Data>().unwrap();
    let kzg_setup = datum.kzg_setup.clone();

    let encrypt_data_res = data.0.deserialize();
    if encrypt_data_res.is_none() {
        log::error!("can't deserialize encrypt_data");
        return HttpResponse::BadRequest().finish();
    }
    let encrypt_data = encrypt_data_res.unwrap();

    let mut pks = encrypt_data.pks;

    let mut rng = OsRng;
    
    let l = log2(encrypt_data.n) as usize - 1;
    let lagrange_helper = &datum.lagrange_helpers[l];

    let mut sk_zero: SecretKey<E> = SecretKey::new(&mut rng);
    sk_zero.nullify();
    pks.insert(0, get_pk_exp(&sk_zero, 0, encrypt_data.n, &lagrange_helper));

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