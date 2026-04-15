# go-wolfssl API Coverage

This document tracks which wolfSSL / wolfcrypt C APIs are wrapped in Go,
and which are not yet covered. The wolfSSL C library and the wolfSSL JNI
bindings (`wolfssljni`) are used as the reference for "complete" coverage.

Legend: ✅ wrapped · ❌ not wrapped · ⚠️ partial

---

## Symmetric Encryption

### AES (`wolfssl/wolfcrypt/aes.h`)

| Function / Feature | Status | Notes |
|---|---|---|
| `wc_AesInit` / `wc_AesFree` | ✅ | |
| `wc_AesAllocAligned` / `wc_AesFreeAllocAligned` | ✅ | aligned heap alloc for AES-NI |
| `wc_AesSetKey` / `wc_AesSetIV` | ✅ | |
| `wc_AesCbcEncrypt` / `wc_AesCbcDecrypt` | ✅ | |
| `wc_AesGcmSetKey` | ✅ | |
| `wc_AesGcmEncrypt` / `wc_AesGcmDecrypt` | ✅ | one-shot |
| `wc_AesGcmEncryptInit` / `Update` / `Final` | ❌ | streaming GCM not wrapped |
| `wc_AesGcmDecryptInit` / `Update` / `Final` | ❌ | streaming GCM not wrapped |
| AES-ECB | ❌ | |
| AES-OFB | ❌ | |
| AES-CFB (1-bit, 8-bit) | ❌ | |
| AES-XTS (`wc_AesXtsInit`, `wc_AesXtsEncryptSector`, …) | ❌ | disk encryption |
| AES-EAX (`wc_AesEaxInit`, `wc_AesEaxEncrypt/DecryptUpdate/Final`) | ❌ | authenticated mode |
| AES-CTS (`wc_AesCtsEncrypt/Decrypt`) | ❌ | |
| `wc_AesNew` / `wc_AesDelete` (heap alloc helpers) | ❌ | |

### ChaCha20 / Poly1305 (`wolfssl/wolfcrypt/chacha.h`, `chacha20_poly1305.h`, `poly1305.h`)

| Function / Feature | Status | Notes |
|---|---|---|
| `wc_ChaCha20Poly1305_Encrypt` / `Decrypt` | ✅ | one-shot AEAD |
| `wc_XChaCha20Poly1305_Encrypt` / `Decrypt` | ✅ | one-shot AEAD |
| `wc_ChaCha20Poly1305_Init` / `UpdateAad` / `UpdateData` / `Final` | ❌ | streaming AEAD not wrapped |
| `wc_Chacha_SetKey` / `wc_Chacha_SetIV` / `wc_Chacha_Process` | ❌ | raw ChaCha20 stream cipher |
| `wc_XChacha_SetKey` | ❌ | raw XChaCha20 |
| `wc_Poly1305Init` / `wc_Poly1305Update` / `wc_Poly1305Final` | ❌ | standalone Poly1305 MAC |

### Other Symmetric Ciphers

| Algorithm | Status | Notes |
|---|---|---|
| Triple-DES (`wolfssl/wolfcrypt/des3.h`) | ❌ | legacy |
| RC4 / ARC4 (`wolfssl/wolfcrypt/arc4.h`) | ❌ | legacy |
| Camellia (`wolfssl/wolfcrypt/camellia.h`) | ❌ | |
| SM4 (`wolfssl/wolfcrypt/sm4.h`) | ❌ | Chinese standard |

---

## Hash Functions

### One-Shot Hashes (`wolfssl/wolfcrypt/hash.h`)

| Function | Status | Notes |
|---|---|---|
| `wc_Md5Hash` | ✅ | |
| `wc_ShaHash` (SHA-1) | ✅ | |
| `wc_Sha256Hash` | ✅ | |
| `wc_Sha384Hash` | ✅ | |
| `wc_Sha512Hash` | ✅ | |
| `wc_Sha224Hash` | ❌ | |
| `wc_Sha512_224Hash` | ❌ | |
| `wc_Sha512_256Hash` | ❌ | |
| `wc_Sha3_224Hash` | ❌ | |
| `wc_Sha3_256Hash` | ❌ | |
| `wc_Sha3_384Hash` | ❌ | |
| `wc_Sha3_512Hash` | ❌ | |
| `wc_Shake128Hash` / `wc_Shake256Hash` | ❌ | |
| `wc_Sm3Hash` | ❌ | Chinese standard |
| Generic `wc_Hash` (unified one-shot) | ❌ | |

### Streaming SHA (`wolfssl/wolfcrypt/sha256.h`, `sha512.h`, `sha3.h`)

| Function | Status | Notes |
|---|---|---|
| `wc_InitSha256_ex` / `wc_Sha256Update` / `wc_Sha256Final` / `wc_Sha256Free` | ✅ | |
| `wc_Sha256Copy` | ❌ | |
| Streaming SHA-1 | ❌ | |
| Streaming SHA-224 | ❌ | |
| Streaming SHA-384 | ❌ | |
| Streaming SHA-512 | ❌ | |
| Streaming SHA-512/224 / SHA-512/256 | ❌ | |
| Streaming SHA-3 (224 / 256 / 384 / 512) | ❌ | |
| Streaming SHAKE128 / SHAKE256 | ❌ | |
| Generic streaming `wc_HashInit` / `wc_HashUpdate` / `wc_HashFinal` | ❌ | |

### BLAKE2 (`wolfssl/wolfcrypt/blake2.h`)

| Function | Status | Notes |
|---|---|---|
| `wc_InitBlake2s` / `wc_Blake2sUpdate` / `wc_Blake2sFinal` | ✅ | |
| `wc_InitBlake2s_WithKey` | ✅ | keyed |
| `Wc_Blake2s_HMAC` (composite Go helper) | ✅ | |
| `wc_InitBlake2b` / `wc_Blake2bUpdate` / `wc_Blake2bFinal` | ❌ | BLAKE2b not wrapped |
| `wc_InitBlake2b_WithKey` | ❌ | |
| `wc_Blake2bHmacInit` / `wc_Blake2bHmacUpdate` / `wc_Blake2bHmacFinal` | ❌ | |

### Other Hash Primitives

| Algorithm | Status | Notes |
|---|---|---|
| SipHash (`wolfssl/wolfcrypt/siphash.h`) | ❌ | lightweight DoS-resistant hash |

---

## MAC / Authentication

### HMAC (`wolfssl/wolfcrypt/hmac.h`)

| Function | Status | Notes |
|---|---|---|
| `wc_HmacInit` / `wc_HmacFree` | ✅ | |
| `wc_HmacAllocAligned` / `wc_HmacFreeAllocAligned` | ✅ | |
| `wc_HmacSetKey` / `wc_HmacUpdate` / `wc_HmacFinal` | ✅ | |
| `wc_HmacCopy` | ❌ | |
| `wc_HmacSizeByType` | ❌ | |

---

## Key Derivation Functions

### HKDF (`wolfssl/wolfcrypt/hmac.h`)

| Function | Status | Notes |
|---|---|---|
| `wc_HKDF` (one-shot) | ✅ | |
| `wc_HKDF_Extract` / `wc_HKDF_Extract_ex` | ❌ | separate extract step |
| `wc_HKDF_Expand` / `wc_HKDF_Expand_ex` | ❌ | separate expand step |

### Password-Based KDF

| Function | Status | Notes |
|---|---|---|
| `wc_PBKDF2` | ✅ | |
| PBKDF1 | ❌ | |
| scrypt | ❌ | |
| bcrypt | ❌ | |
| Argon2 | ❌ | |

### TLS / Protocol KDFs (`wolfssl/wolfcrypt/kdf.h`)

| Function | Status | Notes |
|---|---|---|
| `wc_PRF_TLSv1` | ❌ | TLS 1.0 PRF |
| `wc_PRF` / `wc_PRF_TLS` | ❌ | generic TLS PRF |
| `wc_Tls13_HKDF_Extract` | ❌ | TLS 1.3 |
| `wc_Tls13_HKDF_Expand_Label` | ❌ | TLS 1.3 |
| `wc_SSH_KDF` | ❌ | SSH key derivation |
| `wc_SRTP_KDF` / `wc_SRTCP_KDF` | ❌ | SRTP/SRTCP |
| `wc_KDA_KDF_onestep` / `_twostep_cmac` | ❌ | |
| PKCS#12 KDF (`wc_PKCS12_PBKDF`) | ❌ | |

---

## Asymmetric Cryptography

### RSA (`wolfssl/wolfcrypt/rsa.h`)

**RSA is entirely absent from the Go bindings.**

| Function / Feature | Status | Notes |
|---|---|---|
| `wc_RsaInit` / `wc_RsaFree` | ❌ | |
| `wc_RsaPublicEncrypt` / `wc_RsaPrivateDecrypt` | ❌ | PKCS#1 v1.5 |
| `wc_RsaPublicEncrypt_ex` / `wc_RsaPrivateDecrypt_ex` | ❌ | OAEP variants |
| `wc_RsaSSL_Sign` / `wc_RsaSSL_Verify` | ❌ | PKCS#1 v1.5 sign |
| `wc_RsaPSS_Sign` / `wc_RsaPSS_Verify` | ❌ | PSS sign |
| `wc_RsaPrivateKeyDecode` / `wc_RsaPublicKeyDecode` | ❌ | DER key import |
| `wc_RsaFlattenPublicKey` / `wc_RsaExportKey` | ❌ | key export |
| `wc_RsaEncryptSize` / `wc_RsaPrivateKeyValidate` | ❌ | |

### ECC (`wolfssl/wolfcrypt/ecc.h`)

| Function | Status | Notes |
|---|---|---|
| `wc_ecc_init` / `wc_ecc_free` | ✅ | |
| `wc_ecc_make_key` | ✅ | |
| `wc_ecc_make_key_ex` / `wc_ecc_make_key_ex2` | ❌ | extended variants |
| `wc_ecc_make_pub` | ✅ | (as `Wc_ecc_make_pub_in_priv`) |
| `wc_ecc_set_rng` | ✅ | |
| `wc_ecc_sign_hash` | ✅ | |
| `wc_ecc_sign_hash_ex` | ❌ | deterministic K |
| `wc_ecc_verify_hash` | ✅ | |
| `wc_ecc_verify_hash_ex` | ❌ | |
| `wc_ecc_shared_secret` | ✅ | |
| `wc_ecc_shared_secret_ex` | ❌ | |
| `wc_ecc_check_key` | ✅ | |
| `wc_ecc_export_private_only` | ✅ | |
| `wc_ecc_export_x963_ex` | ✅ | compressed/uncompressed |
| `wc_ecc_import_private_key_ex` | ✅ | |
| `wc_ecc_import_x963_ex` | ✅ | |
| `wc_EccPublicKeyDecode` | ✅ | DER import |
| `wc_ecc_init_ex` | ❌ | device ID variant |
| `wc_ecc_key_new` / `wc_ecc_key_free` | ❌ | heap alloc helpers |
| `wc_ecc_get_curve_params` / `wc_ecc_set_curve` | ❌ | |
| `wc_ecc_is_point` / `wc_ecc_get_generator` | ❌ | |
| `wc_ecc_get_name` | ❌ | |
| `wc_ecc_curve_cache_init` / `wc_ecc_curve_cache_free` | ❌ | |

### Ed25519 (`wolfssl/wolfcrypt/ed25519.h`)

**Ed25519 is entirely absent from the Go bindings.**

| Function / Feature | Status | Notes |
|---|---|---|
| `wc_ed25519_init` / `wc_ed25519_free` | ❌ | |
| `wc_ed25519_make_key` | ❌ | |
| `wc_ed25519_sign_msg` | ❌ | PureEd25519 |
| `wc_ed25519ctx_sign_msg` | ❌ | Ed25519ctx |
| `wc_ed25519ph_sign_msg` | ❌ | Ed25519ph (pre-hash) |
| `wc_ed25519_verify_msg` | ❌ | |
| `wc_ed25519ctx_verify_msg` | ❌ | |
| `wc_ed25519ph_verify_msg` | ❌ | |
| `wc_ed25519_import_public` / `wc_ed25519_import_private_key` | ❌ | |
| `wc_ed25519_export_private` / `wc_ed25519_export_public` | ❌ | |
| `wc_ed25519_check_key` | ❌ | |

### Curve25519 / X25519 (`wolfssl/wolfcrypt/curve25519.h`)

| Function | Status | Notes |
|---|---|---|
| `wc_curve25519_init` / `wc_curve25519_free` | ✅ | |
| `wc_curve25519_make_key` | ✅ | |
| `wc_curve25519_make_pub` | ✅ | |
| `wc_curve25519_make_priv` | ✅ | |
| `wc_curve25519_import_private_ex` | ✅ | |
| `wc_curve25519_import_public_ex` | ✅ | |
| `wc_curve25519_export_private_raw` | ✅ | |
| `wc_curve25519_shared_secret_ex` | ✅ | |
| `wc_curve25519_init_ex` | ❌ | device ID variant |
| `wc_curve25519_new` / `wc_curve25519_delete` | ❌ | heap alloc helpers |
| `wc_curve25519_make_pub_blind` / `wc_curve25519_generic_blind` | ❌ | blinded variants |
| `wc_curve25519_set_nonblock` | ❌ | non-blocking mode |

### Ed448 / Curve448 (`wolfssl/wolfcrypt/ed448.h`, `curve448.h`)

**Ed448 and Curve448 are entirely absent from the Go bindings.**

| Feature | Status |
|---|---|
| Ed448 sign / verify | ❌ |
| X448 ECDH | ❌ |
| Key generation, import, export | ❌ |

### Diffie-Hellman (`wolfssl/wolfcrypt/dh.h`)

**DH is entirely absent from the Go bindings.**

| Function / Feature | Status | Notes |
|---|---|---|
| `wc_DhGenerateKeyPair` | ❌ | |
| `wc_DhAgree` / `wc_DhAgree_ct` | ❌ | constant-time variant |
| Named parameters (`wc_DhSetNamedKey`, etc.) | ❌ | |
| Custom parameters (`wc_DhSetKey`, `wc_DhKeyDecode`) | ❌ | |
| Key validation (`wc_DhCheckPubKey`, etc.) | ❌ | |
| Parameter generation (`wc_DhGenerateParams`) | ❌ | |

### Post-Quantum Cryptography

**Post-quantum algorithms are entirely absent from the Go bindings.**

| Algorithm | Status | Notes |
|---|---|---|
| ML-KEM / Kyber (`wolfssl/wolfcrypt/mlkem.h`) | ❌ | NIST PQC standard |
| Dilithium (`wolfssl/wolfcrypt/dilithium.h`) | ❌ | NIST PQC standard |
| Falcon (`wolfssl/wolfcrypt/falcon.h`) | ❌ | NIST PQC standard |
| SPHINCS+ (`wolfssl/wolfcrypt/sphincs.h`) | ❌ | hash-based signatures |

---

## Random Number Generation (`wolfssl/wolfcrypt/random.h`)

| Function | Status | Notes |
|---|---|---|
| `wc_InitRng` | ✅ | |
| `wc_FreeRng` | ✅ | |
| `wc_RNG_GenerateBlock` | ✅ | |
| `wc_InitRng_ex` | ❌ | device ID variant |
| `wc_InitRngNonce` / `wc_InitRngNonce_ex` | ❌ | |
| `wc_RNG_GenerateByte` | ❌ | single-byte variant |
| `wc_rng_new_ex` | ❌ | heap alloc helper |

---

## FIPS (`wolfssl/wolfcrypt/fips.h`)

| Function | Status | Notes |
|---|---|---|
| `wc_SetDefaultFips_Cb` | ✅ | |
| `wc_SetSeed_Cb` | ✅ | (as `Wc_SetDefaultSeed_Cb`) |
| `WC_PRIVATE_KEY_LOCK` / `WC_PRIVATE_KEY_UNLOCK` | ✅ | |
| `wc_RunAllCast_fips` | ✅ | |

---

## TLS / SSL Layer (`wolfssl/ssl.h`)

### Core Init / Cleanup

| Function | Status |
|---|---|
| `wolfSSL_Init` / `wolfSSL_Cleanup` | ✅ |
| `wolfSSL_Debugging_ON` / `OFF` | ✅ |
| `wolfSSL_lib_version` | ✅ |

### Context & Connection

| Function | Status | Notes |
|---|---|---|
| `wolfSSL_CTX_new` / `wolfSSL_CTX_free` | ✅ | |
| `wolfSSL_CTX_new_ex` | ❌ | heap/device variant |
| `wolfSSL_CTX_up_ref` | ❌ | |
| `wolfSSL_new` / `wolfSSL_free` | ✅ | |
| `wolfSSL_write_dup` | ✅ | |
| `wolfSSL_connect` / `wolfSSL_accept` | ✅ | |
| `wolfSSL_read` / `wolfSSL_write` | ✅ | |
| `wolfSSL_read_ex` / `wolfSSL_write_ex` | ❌ | |
| `wolfSSL_peek` | ❌ | |
| `wolfSSL_shutdown` | ✅ | |
| `wolfSSL_set_fd` | ✅ | |
| `wolfSSL_set_read_fd` / `wolfSSL_set_write_fd` | ❌ | split fds |
| `wolfSSL_get_fd` / `wolfSSL_get_wfd` | ❌ | |
| `wolfSSL_get_error` | ✅ | |
| `wolfSSL_ERR_error_string` | ✅ | |
| `wolfSSL_inject` | ❌ | manual record injection |

### Protocol Methods

| Method | Status |
|---|---|
| `wolfTLSv1_2_server_method` / `_client_method` | ✅ |
| `wolfTLSv1_3_server_method` / `_client_method` | ✅ |
| `wolfDTLSv1_2_server_method` / `_client_method` | ✅ |
| `wolfDTLSv1_3_server_method` / `_client_method` | ✅ |
| `wolfSSLv23_method` / `wolfSSLv23_method_ex` (auto-negotiate) | ❌ |

### Certificates & Keys

| Function | Status | Notes |
|---|---|---|
| `wolfSSL_CTX_use_certificate_file` | ✅ | |
| `wolfSSL_CTX_use_PrivateKey_file` | ✅ | |
| `wolfSSL_CTX_load_verify_locations` | ✅ | |
| `wolfSSL_CTX_load_verify_locations_ex` | ❌ | |
| `wolfSSL_CTX_load_system_CA_certs` | ❌ | |
| `wolfSSL_CTX_use_certificate_chain_file` | ❌ | |
| `wolfSSL_CTX_use_AltPrivateKey_file` | ❌ | hybrid cert (PQC) |
| `wolfSSL_CTX_trust_peer_cert` | ❌ | |
| `wolfSSL_use_certificate_file` (per-session) | ❌ | |
| `wolfSSL_use_PrivateKey_file` (per-session) | ❌ | |

### Cipher Suite & Curves

| Function | Status |
|---|---|
| `wolfSSL_CTX_set_cipher_list` | ✅ |
| `wolfSSL_get_cipher_name` | ✅ |
| `wolfSSL_get_version` | ✅ |
| `wolfSSL_get_ciphers` / `wolfSSL_get_ciphers_iana` | ❌ |
| `wolfSSL_set_groups` / `wolfSSL_set1_groups_list` | ❌ |
| `wolfSSL_CTX_set1_sigalgs_list` / `wolfSSL_set1_sigalgs_list` | ❌ |
| `wolfSSL_get_curve_name` | ❌ |
| `wolfSSL_get_shared_ciphers` | ❌ |

### PSK (Pre-Shared Key)

| Function | Status |
|---|---|
| `wolfSSL_CTX_set_psk_server_callback` | ✅ |
| `wolfSSL_CTX_set_psk_client_callback` | ✅ |
| `wolfSSL_CTX_set_psk_server_tls13_callback` | ✅ |
| `wolfSSL_CTX_set_psk_client_tls13_callback` | ✅ |
| `wolfSSL_CTX_use_psk_identity_hint` | ✅ |

### Callbacks

| Callback | Status | Notes |
|---|---|---|
| PSK client/server (TLS 1.2 + 1.3) | ✅ | |
| Custom I/O send/receive | ❌ | `wolfSSL_SetIOSend` / `wolfSSL_SetIORecv` |
| Certificate verify callback | ❌ | `wolfSSL_CTX_set_verify` |
| RSA sign/verify/encrypt/decrypt callback | ❌ | hardware offload |
| ECC sign/verify/shared-secret callback | ❌ | hardware offload |
| Session ticket callback | ❌ | |
| TLS 1.3 secret derivation callback | ❌ | |
| ALPN select callback | ❌ | |
| DTLS cookie generate/verify callback | ❌ | |

### Session Management

| Feature | Status |
|---|---|
| Basic session reuse (implicit) | ⚠️ |
| `wolfSSL_tls_export` / `wolfSSL_tls_import` | ❌ |
| Session ticket | ❌ |
| `wolfSSL_CTX_no_ticket_TLSv13` | ❌ |

### DTLS

| Feature | Status |
|---|---|
| DTLS 1.2 / 1.3 methods | ✅ |
| `wolfSSL_dtls_create_peer` / `wolfSSL_dtls_set_peer` / `wolfSSL_dtls_free_peer` | ✅ |
| `wolfSSL_dtls_export` / `wolfSSL_dtls_import` | ❌ |
| `wolfSSL_dtls_export_state_only` | ❌ |
| `wolfSSL_dtls_set_export` callback | ❌ |
| `wolfSSL_set_dtls_fd_connected` | ❌ |

### TLS Extensions

| Extension | Status |
|---|---|
| ALPN (`wolfSSL_CTX_UseALPN`) | ❌ |
| SNI (`wolfSSL_CTX_UseSNI`) | ❌ |
| Secure renegotiation | ❌ |
| Extended master secret | ❌ |
| Encrypted Client Hello (ECH) | ❌ |
| OCSP stapling | ❌ |
| HRR (HelloRetryRequest) cookie | ❌ |

### Verification

| Feature | Status |
|---|---|
| `wolfSSL_CTX_set_verify` / `wolfSSL_set_verify` | ❌ |
| `wolfSSL_CTX_mutual_auth` / `wolfSSL_mutual_auth` | ❌ |
| Verify depth | ❌ |
| Static memory pools | ❌ |

---

## X.509 / PKI

### Certificate Verification (x509.go)

| Function | Status |
|---|---|
| `X509_STORE_new` / `X509_STORE_free` | ✅ |
| `X509_STORE_load_locations` | ✅ |
| `sk_X509_new_null` / `sk_X509_push` / `sk_X509_free` | ✅ |
| `X509_STORE_CTX_new` / `X509_STORE_CTX_free` / `X509_STORE_CTX_init` | ✅ |
| `X509_verify_cert` | ✅ |
| `wolfSSL_X509_load_certificate_buffer` | ✅ |
| `wolfSSL_X509_get_pubkey_buffer` | ✅ |
| `wolfSSL_i2d_X509` | ✅ |
| `wolfSSL_X509_free` | ✅ |
| `wolfSSL_BIO_new_mem_buf` / `wolfSSL_BIO_free` | ✅ |
| `wolfSSL_ASN1_get_object` / `wolfSSL_d2i_ASN1_OBJECT` / `wolfSSL_ASN1_OBJECT_free` | ✅ |
| `wolfSSL_OBJ_txt2obj` / `wolfSSL_OBJ_cmp` | ✅ |

### Certificate Creation & Manipulation

**Certificate creation is entirely absent from the Go bindings.**

| Feature | Status | Notes |
|---|---|---|
| Certificate generation (self-signed, CA-signed) | ❌ | |
| Certificate signing request (CSR) creation | ❌ | |
| Set subject / issuer | ❌ | |
| Set serial number / validity dates | ❌ | |
| Set public key | ❌ | |
| Add extensions (key usage, EKU, SAN, AKID, SKID, etc.) | ❌ | |
| Sign certificate with private key | ❌ | |
| Export TBS (to-be-signed) | ❌ | |
| `wolfSSL_X509_up_ref` | ❌ | |
| `wolfSSL_get_peer_certificate_chain` | ❌ | |

### Certificate Revocation Lists (CRL)

**CRL support is entirely absent from the Go bindings.**

| Feature | Status |
|---|---|
| CRL creation / signing | ❌ |
| Load / parse CRL | ❌ |
| Check certificate revocation | ❌ |
| `sk_X509_CRL_*` stack operations | ❌ |

### Certificate Extensions Parsing

| Feature | Status |
|---|---|
| Key usage | ❌ |
| Extended key usage | ❌ |
| Basic constraints | ❌ |
| Subject alternative names (SAN) | ❌ |
| Authority key identifier (AKID) | ❌ |
| Subject key identifier (SKID) | ❌ |
| Name constraints | ❌ |
| CRL distribution points | ❌ |
| OCSP URLs | ❌ |

### OCSP

| Feature | Status |
|---|---|
| OCSP enable / disable | ❌ |
| Override OCSP URL | ❌ |
| OCSP response validation | ❌ |

---

## Certificate & Key Formats

| Format | Status | Notes |
|---|---|---|
| DER (decode via wolfSSL X.509 functions) | ⚠️ | load only |
| PEM (decode via wolfSSL X.509 functions) | ⚠️ | load only |
| PKCS#8 key export / import | ❌ | |
| PKCS#7 (signed/enveloped data) | ❌ | `wolfssl/wolfcrypt/pkcs7.h` |
| PKCS#12 (cert + key bundles) | ❌ | `wolfssl/wolfcrypt/pkcs12.h` |

---

## Utilities

### Misc (`wolfssl/wolfcrypt/misc.h`, `coding.h`, `compress.h`)

| Feature | Status | Notes |
|---|---|---|
| Constant-time comparison (`wc_ConstantCompare`) | ✅ | pure Go impl |
| Memory zeroing (`wc_ForceZero`) | ✅ | |
| `wc_memzero_s` / `wc_memcpy_s` | ❌ | |
| Base64 encode / decode | ❌ | `wc_EncodeBase64`, `wc_DecodeBase64` |
| Base64url encode / decode | ❌ | |
| zlib compress / decompress (`wc_Compress`, `wc_DeCompress`) | ❌ | |

---

## Advanced / Platform Features

| Feature | Status | Notes |
|---|---|---|
| Hardware acceleration callbacks (`wolfssl/wolfcrypt/cryptocb.h`) | ❌ | device ID support |
| Asynchronous crypto (`wolfssl/wolfcrypt/async.h`) | ❌ | non-blocking embedded use |
| Static memory pools | ❌ | `wolfSSL_CTX_load_static_memory` |
| Custom logging (`wolfssl/wolfcrypt/logging.h`) | ❌ | `wolfSSL_SetLoggingCb` |

---

## Summary

| Area | Wrapped | Missing (approx.) |
|---|---|---|
| AES | CBC + GCM (one-shot) | ECB, OFB, CFB, XTS, EAX, CTS, streaming GCM |
| ChaCha20 / Poly1305 | AEAD one-shot | Raw ChaCha20, raw Poly1305, streaming AEAD |
| Other symmetric | — | 3DES, RC4, Camellia, SM4 |
| Hashes (one-shot) | MD5, SHA-1/256/384/512 | SHA-224, SHA-512/224/256, SHA-3, SHAKE, SM3 |
| Hashes (streaming) | SHA-256 only | All others |
| BLAKE2 | BLAKE2s | BLAKE2b |
| HMAC | Full streaming | Copy, size query |
| HKDF | One-shot | Extract/Expand split |
| Password KDF | PBKDF2 | scrypt, bcrypt, Argon2 |
| TLS/Protocol KDF | — | TLS PRF, TLS 1.3 label expand, SSH, SRTP |
| RSA | **nothing** | Encrypt, decrypt, sign, verify, PSS, key I/O |
| ECC (P-curves) | Core ops | Extended variants, curve introspection |
| Ed25519 | **nothing** | Sign, verify, key gen/import/export |
| Curve448 / Ed448 | **nothing** | Full API |
| DH | **nothing** | Full API |
| Post-quantum | **nothing** | ML-KEM, Dilithium, Falcon, SPHINCS+ |
| RNG | Core | Nonce variants, byte variant, heap alloc |
| TLS core | Basic client/server | Auto-negotiate method, split FDs, inject |
| TLS certs/keys | File-based load | Chain file, alt key, per-session load |
| TLS callbacks | PSK only | I/O, verify, RSA/ECC offload, session, ALPN |
| TLS extensions | — | ALPN, SNI, ECH, renegotiation, EMS, OCSP staple |
| TLS session mgmt | — | Export/import, tickets |
| DTLS | Methods + peer addr | Export/import state, connected UDP |
| X.509 verify | Core path | Peer chain, extension parsing |
| X.509 create | **nothing** | Cert gen, CSR, CRL, signing |
| OCSP | **nothing** | Enable, override, validate |
| Cert formats | DER/PEM load only | PKCS#8 export, PKCS#7, PKCS#12 |
| Utilities | Const-compare, zero | Base64, compression |
| Platform | FIPS callbacks | CryptoCb, async, static memory, logging |
