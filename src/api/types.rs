use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;

use aes::Aes256;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use block_modes::Cbc;
use block_modes::block_padding::Pkcs7;

use crate::encryption::Ciphertext;
use crate::kzg::UniversalParams;
use crate::setup::{PublicKey, SecretKey};

use prost::{self, Message};

pub type E = Bls12_381;
pub type G2 = <E as Pairing>::G2;
pub type G1 = <E as Pairing>::G1;
pub type Aes256Cbc = Cbc<Aes256, Pkcs7>;

#[derive(Clone)]
pub struct Data {
    pub kzg_setup: UniversalParams<E>,
    pub sk: SecretKey<E>
}

// VerifyPart

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct VerifyPart {
    pub gamma_g2: G2,
    pub pk: PublicKey<E>,
    pub part_dec: G2
}

#[derive(Clone, Eq, PartialEq, Message)]
pub struct VerifyPartRequest {
    #[prost(bytes, tag="1")]
    pub pk: Vec<u8>,
    #[prost(bytes, tag="2")]
    pub gamma_g2: Vec<u8>,
    #[prost(bytes, tag="3")]
    pub part_dec: Vec<u8>
}

// Encrypt

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct Encrypt {
    pub msg: Vec<u8>,
    pub pks: Vec<PublicKey<E>>,
    pub t: usize,
    pub n: usize
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct EncryptRequest {
    #[prost(bytes, tag="1")]
    pub msg: Vec<u8>,
    #[prost(bytes, repeated, tag="2")]
    pub pks: Vec<Vec<u8>>,
    #[prost(uint64, tag="3")]
    pub t: u64,
    #[prost(uint64, tag="4")]
    pub n: u64
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct EncryptResponse {
    #[prost(bytes, tag="1")]
    pub enc: Vec<u8>,
    #[prost(bytes, tag="2")]
    pub sa1: Vec<u8>,
    #[prost(bytes, tag="3")]
    pub sa2: Vec<u8>,
    #[prost(bytes, tag="4")]
    pub iv: Vec<u8>,
    #[prost(bytes, tag="5")]
    pub gamma_g2: Vec<u8>
}

impl EncryptResponse {
    pub fn new(enc: Vec<u8>, ct: Ciphertext<E>, iv: Vec<u8>) -> Self {
        let mut sa1 = Vec::new();
        let mut res = ct.sa1.serialize_compressed(&mut sa1);
        if res.is_err() {
            log::error!("can't serialize sa1");
        }

        let mut sa2 = Vec::new();
        res = ct.sa2.serialize_compressed(&mut sa2);
        if res.is_err() {
            log::error!("can't serialize sa1");
        }

        let mut gamma_g2 = Vec::new();
        res = ct.gamma_g2.serialize_compressed(&mut gamma_g2);
        if res.is_err() {
            log::error!("can't serialize sa1");
        }

        EncryptResponse {
            enc,
            sa1,
            sa2,
            iv,
            gamma_g2
        }
    }
}


// DecryptParams

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
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

#[derive(Clone, PartialEq, Eq, Message)]
pub struct DecryptParamsRequest {
    #[prost(bytes, tag="1")]
    pub enc: Vec<u8>,
    #[prost(bytes, repeated, tag="2")]
    pub pks: Vec<Vec<u8>>,
    #[prost(bytes, repeated, tag="3")]
    pub parts: Vec<Vec<u8>>,
    #[prost(bytes, tag="4")]
    pub sa1: Vec<u8>,
    #[prost(bytes, tag="5")]
    pub sa2: Vec<u8>,
    #[prost(bytes, tag="6")]
    pub iv: Vec<u8>,
    #[prost(uint64, tag="7")]
    pub t: u64,
    #[prost(uint64, tag="8")]
    pub n: u64
}

// Gamma_G2

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct GammaG2 {
    pub gamma_g2: G2
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct GammaG2Request{
    #[prost(bytes, tag="1")]
    pub gamma_g2: Vec<u8>
}

// Result
#[derive(Clone, PartialEq, Eq, Message)]
pub struct Response {
    #[prost(bytes, tag="1")]
    pub result: Vec<u8>
}