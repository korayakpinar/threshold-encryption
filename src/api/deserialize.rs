use std::io::Cursor;

use crate::{api::types::*, setup::PublicKey};
use ark_serialize::CanonicalDeserialize;

/*

pub struct DecryptParams {
    pub enc: Vec<u8>,
    pub pks: Vec<PublicKey<E>>,
    pub parts: Vec<G2>,
    pub sa1: [G1; 2],
    pub sa2: [G2; 6],
    pub iv: Vec<u8>,
    pub n: usize,
    pub t: usize
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct VerifyPart {
    pub gamma_g2: G2,
    pub pk: PublicKey<E>,
    pub part_dec: G2
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct PublicKey<E: Pairing> {
    pub id: usize,
    pub bls_pk: E::G1,          //BLS pk
    pub sk_li: E::G1,           //hint
    pub sk_li_minus0: E::G1,    //hint
    pub sk_li_by_z: Vec<E::G1>, //hint
    pub sk_li_by_ta: E::G1,    //hint
}

*/

pub fn deserialize_decrypt_params(proto: DecryptParamsProto) -> Option<DecryptParams> { 
    let mut cur = Cursor::new(proto.sa1);
    let tmp_sa1 = CanonicalDeserialize::deserialize_compressed(cur);
    if tmp_sa1.is_err() {
        return None;
    }
    let sa1: [G1; 2] = tmp_sa1.unwrap();

    cur = Cursor::new(proto.sa2);
    let tmp_sa2 = CanonicalDeserialize::deserialize_compressed(cur);
    if tmp_sa2.is_err() {
        return None;
    }
    let sa2: [G2; 6] = tmp_sa2.unwrap();

    let mut parts = Vec::new();
    for part in proto.parts {
        cur = Cursor::new(part);
        let tmp_part = CanonicalDeserialize::deserialize_compressed(cur);
        if tmp_part.is_err() {
            return None;
        }
        parts.push(tmp_part.unwrap());
    }

    let mut pks = Vec::new();
    for pk in proto.pks {
        cur = Cursor::new(pk);
        let tmp_pk = CanonicalDeserialize::deserialize_compressed(cur);
        if tmp_pk.is_err() {
            return None;
        }
        pks.push(tmp_pk.unwrap());
    }
    let tmp_usize = proto.n.try_into();
    if tmp_usize.is_err() {
        return None;
    }
    let n = tmp_usize.unwrap();

    let tmp_usize = proto.t.try_into();
    if tmp_usize.is_err() {
        return None;
    }
    let t = tmp_usize.unwrap();

    Option::from(
        DecryptParams {
            enc: proto.enc,
            pks,
            parts,
            sa1,
            sa2,
            iv: proto.iv,
            n,
            t
        }
    )
}

pub fn deserialize_gamma_g2(proto: GammaG2Proto) -> Option<GammaG2> {
    let cur = Cursor::new(proto.gamma_g2);
    let tmp = CanonicalDeserialize::deserialize_compressed(cur);
    if tmp.is_err() {
        return None;
    }
    let gamma_g2 = tmp.unwrap();
    Option::from(
        GammaG2 {
            gamma_g2
        }
    )
}

pub fn deserialize_verify_part(proto: VerifyPartProto) -> Option<VerifyPart> {
    let mut cur = Cursor::new(proto.gamma_g2);
    let mut tmp_g2 = CanonicalDeserialize::deserialize_compressed(cur);
    if tmp_g2.is_err() {
        return None;
    }
    let gamma_g2 = tmp_g2.unwrap();

    cur = Cursor::new(proto.pk);
    let tmp_pk = CanonicalDeserialize::deserialize_compressed(cur);
    if tmp_pk.is_err() {
        return None;
    }
    let pk = tmp_pk.unwrap();

    cur = Cursor::new(proto.part_dec);
    tmp_g2 = CanonicalDeserialize::deserialize_compressed(cur);
    if tmp_g2.is_err() {
        return None;
    }
    let part_dec = tmp_g2.unwrap();

    Option::from(
        VerifyPart {
            gamma_g2,
            pk,
            part_dec
        }
    )
}