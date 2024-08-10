use actix_protobuf::{ProtoBuf, ProtoBufResponseBuilder};
use actix_web::{HttpRequest, HttpResponse};

use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::*;

use crate::api::types::*;
use crate::utils::lagrange_poly;

pub async fn get_pk_route(config: HttpRequest, data: ProtoBuf<PKRequest>) -> HttpResponse {
    let datum = config.app_data::<Data>().unwrap();
    let sk = &datum.sk;
    let params = &datum.kzg_setup;

    let pk_res = data.0.deserialize();
    if pk_res.is_none() {
        log::error!("can't deserialize pk request");
        return HttpResponse::InternalServerError().finish();
    }
    let pk = pk_res.unwrap();

    let lagrange_polys: Vec<DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>> = (0..pk.n)
        .map(|j| lagrange_poly(pk.n, j))
        .collect();

    let pk = sk.get_pk(pk.id + 1, params, pk.n, &lagrange_polys).await;
    
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