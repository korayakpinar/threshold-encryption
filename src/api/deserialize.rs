use std::{collections::HashMap, io::Cursor};

use crate::api::types::*;
use ark_serialize::CanonicalDeserialize;

pub fn deserialize_decrypt_params(proto: DecryptRequest) -> Option<Decrypt> { 
    let cur = Cursor::new(proto.sa1);
    let tmp_sa1 = CanonicalDeserialize::deserialize_compressed(cur);
    if tmp_sa1.is_err() {
        log::error!("can't deserialize sa1");
        return None;
    }
    let sa1: [G1; 2] = tmp_sa1.unwrap();

    let q = Cursor::new(proto.sa2);
    let tmp_sa2 = CanonicalDeserialize::deserialize_compressed(q);
    if tmp_sa2.is_err() {
        log::error!("can't deserialize sa2");
        return None;
    }
    let sa2: [G2; 6] = tmp_sa2.unwrap();

    // println!("{:?}", proto.pks);
    let mut pks = Vec::new();
    for (idx, pk) in proto.pks.iter().enumerate() {
        if pk.is_empty() {
            continue;
        }
        let cur = Cursor::new(pk);
        let tmp_pk = CanonicalDeserialize::deserialize_compressed(cur);
        if tmp_pk.is_err() {
            log::error!("can't deserialize pk {}", idx);
            return None;
        }
        pks.push(tmp_pk.unwrap());
    }

    let mut parts = HashMap::new();
    for part in proto.parts {
        let cur = Cursor::new(part.1);
        let tmp_part = CanonicalDeserialize::deserialize_compressed(cur);
        if tmp_part.is_err() {
            log::error!("can't deserialize part {}", part.0);
            return None;
        }
        parts.insert(part.0 as usize, tmp_part.unwrap());
    }

    let cur = Cursor::new(proto.gamma_g2);
    let tmp_gamma_g2 = CanonicalDeserialize::deserialize_compressed(cur);
    if tmp_gamma_g2.is_err() {
        log::error!("can't deserialize gamma_g2");
        return None;
    }
    let gamma_g2 = tmp_gamma_g2.unwrap();

    Option::from(
        Decrypt {
            enc: proto.enc,
            pks,
            parts,
            gamma_g2,
            sa1,
            sa2,
            iv: proto.iv,
            n: proto.n as usize,
            t: proto.t as usize
        }
    )
}

pub fn deserialize_encrypt(proto: EncryptRequest) -> Option<Encrypt> {
    let mut pks = Vec::new();
    // println!("len: {}", proto.pks.len());
    for (idx, pk) in proto.pks.iter().enumerate() {
        if pk.is_empty() {
            continue;
        }
        let cur = Cursor::new(pk);
        let tmp_pk = CanonicalDeserialize::deserialize_compressed(cur);
        if tmp_pk.is_err() {
            log::error!("can't deserialize pk {}", idx);
            return None;
        }
        pks.push(tmp_pk.unwrap());
    }
    
    Option::from(
        Encrypt {
            msg: proto.msg,
            pks,
            t: proto.t as usize,
            n: proto.n as usize
        }
    )
}

pub fn deserialize_gamma_g2(proto: PartDecRequest) -> Option<PartDec> {
    let cur = Cursor::new(proto.gamma_g2);
    let tmp = CanonicalDeserialize::deserialize_compressed(cur);
    if tmp.is_err() {
        log::error!("can't read gamma_g2");
        return None;
    }
    let gamma_g2 = tmp.unwrap();
    Option::from(
        PartDec {
            gamma_g2
        }
    )
}

pub fn deserialize_verify_part(proto: VerifyPartRequest) -> Option<VerifyPart> {
    let mut cur = Cursor::new(proto.gamma_g2);
    let mut tmp_g2 = CanonicalDeserialize::deserialize_compressed(cur);
    if tmp_g2.is_err() {
        log::error!("can't read gamma_g2");
        return None;
    }
    let gamma_g2 = tmp_g2.unwrap();

    cur = Cursor::new(proto.pk);
    let tmp_pk = CanonicalDeserialize::deserialize_compressed(cur);
    if tmp_pk.is_err() {
        log::error!("can't read pk");
        return None;
    }
    let pk = tmp_pk.unwrap();

    cur = Cursor::new(proto.part_dec);
    tmp_g2 = CanonicalDeserialize::deserialize_compressed(cur);
    if tmp_g2.is_err() {
        log::error!("can't read part_dec");
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

pub fn deserialize_pk_req(proto: PKRequest) -> Option<PK> {
    return Option::from(
        PK {
            id: proto.id as usize,
            n: proto.n as usize
        }
    )
}