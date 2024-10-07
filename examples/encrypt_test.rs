use std::{fs::File, io::Cursor};
use ark_serialize::Read;
use block_modes::BlockMode;
use ark_bls12_381::Bls12_381;
use rand::{rngs::OsRng, Rng};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use silent_threshold::{
    api::types::Aes256Cbc,
    encryption::encrypt,
    kzg::UniversalParams,
    setup::{get_pk_exp, AggregateKey, PublicKey, SecretKey},
    utils::{LagrangePoly, LagrangePolyHelper}
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use reqwest::Client;
use ethers::prelude::*;
use transaction::eip2718::TypedTransaction;

type E = Bls12_381;

// Constants
const N: usize = 512;
const K: usize = 511;
const T: usize = 2;
const URL: &str = "https://eldergleam.legendrelabs.xyz:8545"; //"https://ethereum-holesky-rpc.publicnode.com"; //
const ETH_VALUE: f64 = 0.000001 * 1e18;
const FROM: &str = "4562d7fdf20d2661b8b7e174d3a63458830c8161006d2749ea3022a796507c8e";
const TO: &str = "0x587EC4234B450310a9B64984b523CC1D077112f8";
const DATA: &str = "Whats up bro"; 

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

#[derive(Serialize, Deserialize, Debug)]
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

fn encrypt_transaction_with_preloaded(
    plaintext: &[u8],
    agg_key: &AggregateKey<E>,
    params: &UniversalParams<E>,
    t: usize,
) -> EncryptedTransactionParams {
    let mut rng = OsRng;

    // Encrypt the transaction
    println!("Encrypting transaction");
    let ct = encrypt::<E>(agg_key, t, params);
    println!("Transaction encrypted\n");
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
        pk_ids: (0..N as u64 - 1).collect(),
        gamma_g2,
        threshold: t as u64,
        sa1,
        sa2,
        iv: iv.to_vec(),
    }
}

fn load_lagrange_helper(n: usize) -> LagrangePolyHelper {
    let mut file = File::open(format!("./lagrangehelpers/{}", n)).unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    let cur = Cursor::new(contents);
    LagrangePolyHelper::deserialize_compressed_unchecked(cur).unwrap()
}

fn load_universal_params() -> UniversalParams<E> {
    let mut file = File::open("transcript-512").unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    let cur = Cursor::new(contents);
    UniversalParams::deserialize_compressed_unchecked(cur).unwrap()
}

fn generate_keys(k: usize, lagrange_helper: &LagrangePolyHelper) -> (Vec<SecretKey<E>>, Vec<PublicKey<E>>) {
    let mut sk = Vec::new();
    let mut pk = Vec::new();
    let mut rng = OsRng;

    sk.push(SecretKey::<E>::new(&mut rng));
    sk[0].nullify();

    let lagrange_poly = LagrangePoly::new(0, lagrange_helper);
    pk.push(get_pk_exp(&sk[0], 0, &lagrange_poly));

    for i in 1..k {
        println!("Generating key {}", i);
        let mut file = File::open(format!("keys/{}-pk", i)).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        let cur = Cursor::new(contents);
        let key = PublicKey::<E>::deserialize_uncompressed_unchecked(cur).unwrap();
        pk.push(key);
        
        let mut file = File::open(format!("keys/{}-bls", i)).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        let cur = Cursor::new(contents);
        let key = SecretKey::<E>::deserialize_compressed_unchecked(cur).unwrap();
        sk.push(key);
    }

    (sk, pk)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load necessary files and initialize parameters once
    println!("Loading lagrange helper");
    let lagrange_helper = load_lagrange_helper(N);
    println!("Lagrange helper loaded\n");
    println!("Loading universal params");
    let params = load_universal_params();
    println!("Universal params loaded\n");

    // Generate keys once
    println!("Generating keys");
    let (_sk, pk) = generate_keys(K + 1, &lagrange_helper);
    println!("Keys generated\n");

    // Create the aggregate key once
    println!("Aggregating keys");
    let agg_key = AggregateKey::<E>::new(pk.clone(), N, &params);
    println!("Keys aggregated\n");

    // Initialize the wallet and client
    let wallet: LocalWallet = FROM.parse()?;
    println!("Wallet: {:?}", wallet);
    let provider = Provider::<Http>::try_from(URL)?;
    let client = SignerMiddleware::new(provider, wallet.with_chain_id(17000u64));

    // Prepare common transaction parameters
    let to_address: Address = TO.parse()?; 
    let value: U256 = U256::from(ETH_VALUE as u64);
    let chain_id = 17000u64;

    // Determine the number of transactions you want to send
    let num_transactions = 32; // For example, send 5 transactions

    // Get the current nonce for each transaction
    let mut nonce = client.get_transaction_count(client.address(), Some(BlockNumber::Pending.into())).await.unwrap();

    for i in 0..num_transactions {
        // Clone necessary data for the async task
        let client = client.clone();
        let agg_key = agg_key.clone();
        let params = params.clone();
        let to_address = to_address.clone();
        let value = value.clone();

        // Spawn a new task for each transaction
        println!("Processing transaction {}", i + 1);

        
        nonce += U256::from(i);
        // Create the transaction
        let tx = TransactionRequest::new()
            .to(to_address)
            .value(value)
            .data(DATA.as_bytes().to_vec())
            .from(client.address())
            .chain_id(chain_id)
            .gas(22000u64)
            .nonce(nonce);

        let mut typed_tx: TypedTransaction = tx.into();
        let gas_price = client.get_gas_price().await.unwrap();
        let gas = client.estimate_gas(&typed_tx.clone(), None).await.unwrap();

        typed_tx.set_gas_price(gas_price).set_gas(gas);

        // Sign the transaction
        let sig = client.sign_transaction(&typed_tx, client.address()).await.unwrap();
        let signed_tx = typed_tx.rlp_signed(&sig);

        let hash = typed_tx.hash(&sig);
        println!("Signed transaction: {:?}", signed_tx);

        // Encrypt the transaction using the preloaded data
        let mut params_enc = encrypt_transaction_with_preloaded(
            &signed_tx.0,
            &agg_key,
            &params,
            T,
        );
        params_enc.hash = format!("{:?}", hash);

        // Prepare the request
        let request = EncryptedTransactionRequest {
            id: 1,
            jsonrpc: "2.0".to_string(),
            method: "eth_sendEncryptedTransaction".to_string(),
            params: vec![params_enc],
        };

        // Create a new HTTP client
        let http_client = Client::new();

        // Send the POST request
        let response = http_client.post(URL)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await.unwrap();

        // Check if the request was successful
        if response.status().is_success() {
            let response_body = response.text().await.unwrap();
            println!("Successfully sent encrypted transaction {}. Response: {}", i + 1, response_body);
        } else {
            println!("Failed to send encrypted transaction {}. Status: {}", i + 1, response.status());
            let error_body = response.text().await.unwrap();
            println!("Error response: {}", error_body);
        } 

        println!("Transaction {} processed", i + 1);
        
    }

    Ok(())
}