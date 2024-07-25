# Silent Threshold Encryption [ePrint:2024/263](https://eprint.iacr.org/2024/263)

Rust implementation of the silent-threshold encryption introduced in [ePrint:2024/263](https://eprint.iacr.org/2024/263).

Use ```cargo bench``` to benchmark `setup`, `encryption`, and `decryption`.

Use ```cargo run --example endtoend``` to check correctness of the implementation.

**WARNING:** This is an extended implementation of the original paper author's Proof of Concept code. Use at your own risk.

## API Documentation

### /decrypt

**Endpoint:** `/decrypt`

**Method:** `POST`

**Request Parameters:**

- `enc` (bytes): Encrypted data.
- `pks` (repeated bytes): Public keys.
- `parts` (map<uint64, bytes>): Decryption parts.
- `gamma_g2` (bytes): Gamma value in G2.
- `sa1` (bytes): SA1 value.
- `sa2` (bytes): SA2 value.
- `iv` (bytes): Initialization vector.
- `t` (uint64): Threshold.
- `n` (uint64): Total number of participants.

**Response:**

- `result` (bytes): Decrypted data.

**Error Responses:**

- `400`: Unable to deserialize the proto.
- `451`: Unable to decrypt the data.

---

### /encrypt

**Endpoint:** `/encrypt`

**Method:** `POST`

**Request Parameters:**

- `msg` (bytes): Message to be encrypted.
- `pks` (repeated bytes): Public keys.
- `t` (uint64): Threshold.
- `n` (uint64): Total number of participants.

**Response:**

- `enc` (bytes): Encrypted data.
- `sa1` (bytes): SA1 value.
- `sa2` (bytes): SA2 value.
- `iv` (bytes): Initialization vector.
- `gamma_g2` (bytes): Gamma value in G2.

**Error Responses:**

- `400`: Unable to deserialize the proto.

---

### /partdec

**Endpoint:** `/partdec`

**Method:** `POST`

**Request Parameters:**

- `gamma_g2` (bytes): Gamma value in G2.

**Response:**

- `result` (bytes): Partial decryption result.

**Error Responses:**

- `400`: Unable to deserialize the proto.

---

### /getpk

**Endpoint:** `/getpk`

**Method:** `POST`

**Request Parameters:**

- `id` (uint64): Participant ID.
- `n` (uint64): Total number of participants.

**Response:**

- `result` (bytes): Public key.

**Error Responses:**

- `400`: Unable to deserialize the proto.

---

### /verifypart

**Endpoint:** `/verifypart`

**Method:** `POST`

**Request Parameters:**

- `pk` (bytes): Public key.
- `gamma_g2` (bytes): Gamma value in G2.
- `part_dec` (bytes): Partial decryption result.

**Response:**

- `200`: Verification succeeded.

**Error Responses:**

- `400`: Unable to deserialize the proto.
- `451`: Verification failed.

## License
This library is released under the MIT License.
