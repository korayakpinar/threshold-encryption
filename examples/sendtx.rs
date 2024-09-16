use std::{fs::File, io::{Cursor, Read}};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use block_modes::BlockMode;
use clap::Parser;
use ethers::{abi::Address, middleware::SignerMiddleware, providers::{Http, Middleware, Provider}, signers::{LocalWallet, Signer}, types::{transaction::eip2718::TypedTransaction, BlockNumber, TransactionRequest}};
use rand::{rngs::OsRng, Rng};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use silent_threshold::{api::types::{Aes256Cbc, E}, encryption::encrypt, kzg::UniversalParams, setup::AggregateKey};
use web3::types::U256;

const URL: &str = "https://banger.build:8545";
const ETH_VALUE: f64 = 0.000001 * 1e18;

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedTransactionRequest {
    #[serde(rename = "id")]
    pub id: i64,
    #[serde(rename = "jsonrpc")]
    pub jsonrpc: String,
    #[serde(rename = "method")]
    pub method: String,
    #[serde(rename = "params")]
    pub params: Vec<EncryptedTransactionParams>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize, Debug)]
pub struct EncryptedTransactionParams {
    #[serde(rename = "hash")]
    pub hash: String,
    #[serde(rename = "encryptedTx")]
    pub encrypted_tx: Vec<u8>,
    #[serde(rename = "pkIDs")]
    pub pk_ids: Vec<u64>,
    #[serde(rename = "gammaG2")]
    pub gamma_g2: Vec<u8>,
    #[serde(rename = "threshold")]
    pub threshold: u64,
    #[serde(rename = "sa1")]
    pub sa1: Vec<u8>,
    #[serde(rename = "sa2")]
    pub sa2: Vec<u8>,
    #[serde(rename = "iv")]
    pub iv: Vec<u8>,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Committee size
    #[arg(short, long)]
    pub n: usize,

    /// Threshold
    #[arg(short, long)]
    pub t: usize,

    /// From (private key)
    #[arg(short, long)]
    pub from: String,

    /// To (0xpublic key)
    #[arg(short, long)]
    pub to: String,

    /// Message to send
    #[arg(short, long)]
    pub message: String
}

fn load_universal_params() -> UniversalParams<E> {
    let mut file = File::open("transcript-512").unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    let cur = Cursor::new(contents);
    println!("Loading universal params...");
    UniversalParams::deserialize_compressed(cur).unwrap()
}

fn load_aggregated_key() -> AggregateKey<E> {
    let mut file = File::open("./aggregatedkey").unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    let cur = Cursor::new(contents);
    println!("Loading aggregated key...");
    AggregateKey::<E>::deserialize_uncompressed_unchecked(cur).unwrap()
}

fn encrypt_transaction(plaintext: &[u8], n: usize, t: usize) -> EncryptedTransactionParams {
    let mut rng = OsRng;

    let aggregated_key = load_aggregated_key();
    let params = load_universal_params();

    println!("Encrypting transaction...");
    let ct = encrypt::<E>(&aggregated_key, t, &params);
    let mut hasher = Sha256::new();
    hasher.update(ct.enc_key.to_string().as_bytes());
    let result = hasher.finalize();
    let key = result.as_slice();

    let iv = &mut [0u8; 16];
    rng.fill(iv);

    let cipher_enc = Aes256Cbc::new_from_slices(key, iv).unwrap();
    let enc = cipher_enc.encrypt_vec(plaintext);

    let mut gamma_g2 = Vec::new();
    ct.gamma_g2.serialize_compressed(&mut gamma_g2).unwrap();

    let mut sa1 = Vec::new();
    ct.sa1.serialize_compressed(&mut sa1).unwrap();

    let mut sa2 = Vec::new();
    ct.sa2.serialize_compressed(&mut sa2).unwrap();

    EncryptedTransactionParams {
        hash: "".to_string(), // This will be filled later with the transaction hash
        encrypted_tx: enc,
        pk_ids: (0..n as u64 - 1).collect(),
        gamma_g2,
        threshold: t as u64,
        sa1,
        sa2,
        iv: iv.to_vec(),
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let wallet: LocalWallet = args.from.parse().unwrap();

    println!("Wallet: {:?}", wallet);
    
    let to_address: Address = args.to.parse().unwrap(); 
    let value = U256::from(ETH_VALUE as u64);
    let provider = Provider::<Http>::try_from(URL).unwrap();
    let client = SignerMiddleware::new(provider, wallet.with_chain_id(17000u64));
    let nonce = client.get_transaction_count(client.address().clone(), Some(BlockNumber::Pending.into())).await.unwrap();
    let tx = TransactionRequest::new().to(to_address).data(args.message.as_bytes().to_vec()).value(value).from(client.address()).chain_id(17000u64).gas(22000u64).nonce(nonce);
   

    let mut typed_tx: TypedTransaction = tx.into();
    let gas_price = client.get_gas_price().await.unwrap();
    let gas = client.estimate_gas(&typed_tx.clone(), None).await.unwrap();

    typed_tx.set_gas_price(gas_price).set_gas(gas);
    let sig = client.sign_transaction(&typed_tx, client.address()).await.unwrap();
    let signed_tx = typed_tx.rlp_signed(&sig);
    
    let hash = typed_tx.hash(&sig);
    println!("{:?}", signed_tx);
    let mut params = encrypt_transaction(&signed_tx.0, args.n, args.t);
    params.hash = format!("{:?}", hash);

    
    println!("Hash: {:?}", params.hash);
    println!("Encrypted tx: {:?}", params.encrypted_tx);
    println!("PK ids: {:?}", params.pk_ids.len());
    println!("Gamma G2: {:?}", params.gamma_g2.len());
    println!("Threshold: {:?}", params.threshold);
    println!("SA1: {:?}", params.sa1.len());
    println!("SA2: {:?}", params.sa2.len());
    println!("IV: {:?}", params.iv);
     
  
    let request = EncryptedTransactionRequest {
        id: 1,
        jsonrpc: "2.0".to_string(),
        method: "eth_sendEncryptedTransaction".to_string(),
        params: vec![params],
    };

    // Create a new HTTP client
    let client = Client::new();

    // Send the POST request
    let response = client.post(URL)
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await;

    let res = response.unwrap();

    // Check if the request was successful
    if res.status().is_success() {
        let response_body = res.text().await.unwrap();
        println!("Successfully sent encrypted transaction. Response: {}", response_body);
    } else {
        println!("Failed to send encrypted transaction. Status: {}", res.status());
        let error_body = res.text().await.unwrap();
        println!("Error response: {}", error_body);
    } 
}