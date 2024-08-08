use actix_protobuf::{ProtoBuf, ProtoBufResponseBuilder};
use actix_web::{HttpRequest, HttpResponse};

use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_std::Zero;

use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use block_modes::BlockMode;

use crate::setup::{AggregateKey, SecretKey};
use crate::decryption::agg_dec;

use crate::api::types::*;
use crate::utils::lagrange_poly;

pub async fn decrypt_route(config: HttpRequest, data: ProtoBuf<DecryptRequest>) -> HttpResponse {
    let datum = config.app_data::<Data>().unwrap();
    let kzg_setup = datum.clone().kzg_setup;

    let params_res = DecryptRequest::deserialize(data.0);
    if params_res.is_none() {
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

    let mut pks = params.pks;

    let lagrange_polys: Vec<DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>> = (0..params.n)
        .map(|j| lagrange_poly(params.n, j))
        .collect();

    pks.insert(0, sk_zero.get_pk(0, &kzg_setup, params.n, &lagrange_polys));

    //println!("{:#?}, {:#?}, {:#?}, {}, {}", partial_decryptions, partial_decryptions.len(), params.parts.len(), params.t, params.n);

    let aggregated = AggregateKey::<E>::new(pks, params.n, &kzg_setup);
    let key = agg_dec(&partial_decryptions, &params.sa1, &params.sa2, params.t, params.n, &selector, &aggregated, &kzg_setup).await;

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