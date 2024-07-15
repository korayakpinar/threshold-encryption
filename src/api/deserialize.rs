use std::io::Cursor;

use crate::api::types::*;
use ark_serialize::CanonicalDeserialize;

pub fn deserialize_decrypt_params(proto: DecryptParamsRequest) -> Option<DecryptParams> { 
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

    let mut parts = Vec::new();
    for (idx, part) in proto.parts.iter().enumerate() {
        let cur = Cursor::new(part);
        let tmp_part = CanonicalDeserialize::deserialize_compressed(cur);
        if tmp_part.is_err() {
            log::error!("can't deserialize part {}", idx);
            return None;
        }
        parts.push(tmp_part.unwrap());
    }

    let mut pks = Vec::new();
    for (idx, pk) in proto.pks.iter().enumerate() {
        let cur = Cursor::new(pk);
        let tmp_pk = CanonicalDeserialize::deserialize_compressed(cur);
        if tmp_pk.is_err() {
            log::error!("can't deserialize pk {}", idx);
            return None;
        }
        pks.push(tmp_pk.unwrap());
    }
    let tmp_usize = proto.n.try_into();
    if tmp_usize.is_err() {
        log::error!("can't read n");
        return None;
    }
    let n = tmp_usize.unwrap();

    let tmp_usize = proto.t.try_into();
    if tmp_usize.is_err() {
        log::error!("can't read t");
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

pub fn deserialize_encrypt(proto: EncryptRequest) -> Option<Encrypt> {
    let mut pks = Vec::new();
    
    for (idx, pk) in proto.pks.iter().enumerate() {
        let cur = Cursor::new(pk);
        let tmp_pk = CanonicalDeserialize::deserialize_compressed(cur);
        if tmp_pk.is_err() {
            log::error!("can't deserialize pk {}", idx);
            return None;
        }
        pks.push(tmp_pk.unwrap());
    }

    let tmp_usize = proto.n.try_into();
    if tmp_usize.is_err() {
        log::error!("can't read n");
        return None;
    }
    let n = tmp_usize.unwrap();

    let tmp_usize = proto.t.try_into();
    if tmp_usize.is_err() {
        log::error!("can't read t");
        return None;
    }
    let t = tmp_usize.unwrap();
    
    Option::from(
        Encrypt {
            msg: proto.msg,
            pks,
            t,
            n
        }
    )
}

pub fn deserialize_gamma_g2(proto: GammaG2Request) -> Option<GammaG2> {
    let cur = Cursor::new(proto.gamma_g2);
    let tmp = CanonicalDeserialize::deserialize_compressed(cur);
    if tmp.is_err() {
        log::error!("can't read gamma_g2");
        return None;
    }
    let gamma_g2 = tmp.unwrap();
    Option::from(
        GammaG2 {
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
    let n_res = proto.n.try_into();
    if n_res.is_err() {
        return None;
    }
    let n = n_res.unwrap();

    let id_res = proto.n.try_into();
    if id_res.is_err() {
        return None;
    }
    let id = id_res.unwrap();

    return Option::from(
        PK {
            id,
            n
        }
    )
}