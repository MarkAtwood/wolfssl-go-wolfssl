/* rsa.go
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

// Package wolfSSL provides Go bindings for the wolfSSL C library.
//
// Thread safety: RsaKey structs are NOT thread-safe. Each goroutine must use
// its own RsaKey instance, or the caller must serialize access externally.

package wolfSSL

// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/rsa.h>
// #include <wolfssl/wolfcrypt/hash.h>
//
// /* Provide stub definitions when RSA is compiled out so that the Go
//    constants and type alias below still compile. */
// #ifdef NO_RSA
// typedef struct RsaKey {} RsaKey;
// #define WC_RSA_PKCSV15_PAD 0
// #define WC_RSA_OAEP_PAD    1
// #define WC_RSA_PSS_PAD     2
// #define WC_RSA_NO_PAD      3
// #define WC_MGF1NONE    0
// #define WC_MGF1SHA1    26
// #define WC_MGF1SHA224  4
// #define WC_MGF1SHA256      1
// #define WC_MGF1SHA384      2
// #define WC_MGF1SHA512      3
// #define WC_MGF1SHA512_224  5
// #define WC_MGF1SHA512_256  6
// #endif
//
// /* ---- Init / Free / Utility -------------------------------------------- */
//
// static int go_wc_InitRsaKey(RsaKey* key, void* heap) {
// #ifndef NO_RSA
//     return wc_InitRsaKey(key, heap);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_InitRsaKey_ex(RsaKey* key, void* heap, int devId) {
// #ifndef NO_RSA
//     return wc_InitRsaKey_ex(key, heap, devId);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_FreeRsaKey(RsaKey* key) {
// #ifndef NO_RSA
//     return wc_FreeRsaKey(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_CheckRsaKey(RsaKey* key) {
// #ifndef NO_RSA
//     return wc_CheckRsaKey(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_RsaEncryptSize(const RsaKey* key) {
// #ifndef NO_RSA
//     return wc_RsaEncryptSize(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- PKCS#1 v1.5 encrypt / decrypt ------------------------------------ */
//
// static int go_wc_RsaPublicEncrypt(const byte* in, word32 inLen,
//         byte* out, word32 outLen, RsaKey* key, WC_RNG* rng) {
// #ifndef NO_RSA
//     return wc_RsaPublicEncrypt(in, inLen, out, outLen, key, rng);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_RsaPrivateDecrypt(const byte* in, word32 inLen,
//         byte* out, word32 outLen, RsaKey* key) {
// #ifndef NO_RSA
//     return wc_RsaPrivateDecrypt(in, inLen, out, outLen, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_RsaPrivateDecryptInline(byte* in, word32 inLen,
//         byte** out, RsaKey* key) {
// #ifndef NO_RSA
//     return wc_RsaPrivateDecryptInline(in, inLen, out, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- OAEP / extended variants ----------------------------------------- */
//
// static int go_wc_RsaPublicEncrypt_ex(const byte* in, word32 inLen,
//         byte* out, word32 outLen, RsaKey* key, WC_RNG* rng,
//         int type, enum wc_HashType hash, int mgf,
//         byte* label, word32 labelSz) {
// #if !defined(NO_RSA) && (!defined(HAVE_FIPS) || \
//         (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION >= 2))
//     return wc_RsaPublicEncrypt_ex(in, inLen, out, outLen, key, rng,
//                                   type, hash, mgf, label, labelSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_RsaPrivateDecrypt_ex(const byte* in, word32 inLen,
//         byte* out, word32 outLen, RsaKey* key,
//         int type, enum wc_HashType hash, int mgf,
//         byte* label, word32 labelSz) {
// #if !defined(NO_RSA) && (!defined(HAVE_FIPS) || \
//         (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION >= 2))
//     return wc_RsaPrivateDecrypt_ex(in, inLen, out, outLen, key,
//                                    type, hash, mgf, label, labelSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- PKCS#1 v1.5 sign / verify ---------------------------------------- */
//
// static int go_wc_RsaSSL_Sign(const byte* in, word32 inLen,
//         byte* out, word32 outLen, RsaKey* key, WC_RNG* rng) {
// #ifndef NO_RSA
//     return wc_RsaSSL_Sign(in, inLen, out, outLen, key, rng);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_RsaSSL_Verify(const byte* in, word32 inLen,
//         byte* out, word32 outLen, RsaKey* key) {
// #ifndef NO_RSA
//     return wc_RsaSSL_Verify(in, inLen, out, outLen, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- PSS sign / verify ------------------------------------------------ */
//
// static int go_wc_RsaPSS_Sign(const byte* in, word32 inLen,
//         byte* out, word32 outLen,
//         enum wc_HashType hash, int mgf,
//         RsaKey* key, WC_RNG* rng) {
// #if !defined(NO_RSA) && defined(WC_RSA_PSS)
//     return wc_RsaPSS_Sign(in, inLen, out, outLen, hash, mgf, key, rng);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_RsaPSS_Sign_ex(const byte* in, word32 inLen,
//         byte* out, word32 outLen,
//         enum wc_HashType hash, int mgf, int saltLen,
//         RsaKey* key, WC_RNG* rng) {
// #if !defined(NO_RSA) && defined(WC_RSA_PSS)
//     return wc_RsaPSS_Sign_ex(in, inLen, out, outLen, hash, mgf, saltLen,
//                               key, rng);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_RsaPSS_Verify(const byte* in, word32 inLen,
//         byte* out, word32 outLen,
//         enum wc_HashType hash, int mgf, RsaKey* key) {
// #if !defined(NO_RSA) && defined(WC_RSA_PSS)
//     return wc_RsaPSS_Verify(in, inLen, out, outLen, hash, mgf, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_RsaPSS_Verify_ex(const byte* in, word32 inLen,
//         byte* out, word32 outLen,
//         enum wc_HashType hash, int mgf, int saltLen, RsaKey* key) {
// #if !defined(NO_RSA) && defined(WC_RSA_PSS)
//     return wc_RsaPSS_Verify_ex(in, inLen, out, outLen, hash, mgf, saltLen,
//                                 key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- Key import / export ---------------------------------------------- */
//
// static int go_wc_RsaPrivateKeyDecode(const byte* input, word32* inOutIdx,
//         RsaKey* key, word32 inSz) {
// #if !defined(NO_RSA) && (!defined(HAVE_FIPS) || \
//         (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION >= 2))
//     return wc_RsaPrivateKeyDecode(input, inOutIdx, key, inSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_RsaPublicKeyDecode(const byte* input, word32* inOutIdx,
//         RsaKey* key, word32 inSz) {
// #if !defined(NO_RSA) && (!defined(HAVE_FIPS) || \
//         (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION >= 2))
//     return wc_RsaPublicKeyDecode(input, inOutIdx, key, inSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_RsaPublicKeyDecodeRaw(const byte* n, word32 nSz,
//         const byte* e, word32 eSz, RsaKey* key) {
// #if !defined(NO_RSA) && (!defined(HAVE_FIPS) || \
//         (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION >= 2))
//     return wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_RsaFlattenPublicKey(const RsaKey* key,
//         byte* e, word32* eSz, byte* n, word32* nSz) {
// #ifndef NO_RSA
//     return wc_RsaFlattenPublicKey(key, e, eSz, n, nSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
import "C"
import (
	"unsafe"
)

// RsaKey is a type alias for the wolfSSL RsaKey struct.
// RsaKey structs are NOT thread-safe; do not share an instance across goroutines
// without external synchronization.
type RsaKey = C.struct_RsaKey

// Padding type constants for RSA operations.
const WC_RSA_PKCSV15_PAD = int(C.WC_RSA_PKCSV15_PAD)
const WC_RSA_OAEP_PAD = int(C.WC_RSA_OAEP_PAD)
const WC_RSA_PSS_PAD = int(C.WC_RSA_PSS_PAD)
const WC_RSA_NO_PAD = int(C.WC_RSA_NO_PAD)

// MGF algorithm constants for RSA-OAEP and RSA-PSS.
const WC_MGF1NONE = int(C.WC_MGF1NONE)
const WC_MGF1SHA1 = int(C.WC_MGF1SHA1)
const WC_MGF1SHA224 = int(C.WC_MGF1SHA224)
const WC_MGF1SHA256 = int(C.WC_MGF1SHA256)
const WC_MGF1SHA384 = int(C.WC_MGF1SHA384)
const WC_MGF1SHA512 = int(C.WC_MGF1SHA512)
const WC_MGF1SHA512_224 = int(C.WC_MGF1SHA512_224)
const WC_MGF1SHA512_256 = int(C.WC_MGF1SHA512_256)

// Wc_InitRsaKey initializes an RsaKey struct.
// heap may be nil to use the default heap.
// Returns 0 on success, negative on error.
func Wc_InitRsaKey(key *C.struct_RsaKey, heap unsafe.Pointer) int {
	return int(C.go_wc_InitRsaKey(key, heap))
}

// Wc_InitRsaKey_ex initializes an RsaKey struct with an explicit device ID.
// heap may be nil. devId should be INVALID_DEVID when not using hardware crypto.
// Returns 0 on success, negative on error.
func Wc_InitRsaKey_ex(key *C.struct_RsaKey, heap unsafe.Pointer, devId int) int {
	return int(C.go_wc_InitRsaKey_ex(key, heap, C.int(devId)))
}

// Wc_FreeRsaKey releases resources held by an RsaKey struct.
// Returns 0 on success, negative on error.
func Wc_FreeRsaKey(key *C.struct_RsaKey) int {
	return int(C.go_wc_FreeRsaKey(key))
}

// Wc_CheckRsaKey validates the internal consistency of an RsaKey struct.
// Returns 0 on success, negative on error.
func Wc_CheckRsaKey(key *C.struct_RsaKey) int {
	return int(C.go_wc_CheckRsaKey(key))
}

// Wc_RsaEncryptSize returns the output size in bytes of an RSA encryption or
// signing operation for the given key. Returns negative on error.
func Wc_RsaEncryptSize(key *C.struct_RsaKey) int {
	return int(C.go_wc_RsaEncryptSize(key))
}

// Wc_RsaPublicEncrypt encrypts in using PKCS#1 v1.5 with the public key.
// outLen must be >= Wc_RsaEncryptSize(key). sz must be <= len(out).
// Returns the number of bytes written to out on success, negative on error.
func Wc_RsaPublicEncrypt(in []byte, inLen int, out []byte, outLen int, key *C.struct_RsaKey, rng *C.struct_WC_RNG) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if outLen < 0 || outLen > len(out) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 || len(out) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_RsaPublicEncrypt(
		(*C.uchar)(unsafe.Pointer(&in[0])), C.word32(inLen),
		(*C.uchar)(unsafe.Pointer(&out[0])), C.word32(outLen),
		key, rng))
}

// Wc_RsaPrivateDecrypt decrypts in using PKCS#1 v1.5 with the private key.
// outLen must be >= the expected plaintext length. sz must be <= len(out).
// Returns the number of plaintext bytes written to out on success, negative on error.
func Wc_RsaPrivateDecrypt(in []byte, inLen int, out []byte, outLen int, key *C.struct_RsaKey) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if outLen < 0 || outLen > len(out) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 || len(out) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_RsaPrivateDecrypt(
		(*C.uchar)(unsafe.Pointer(&in[0])), C.word32(inLen),
		(*C.uchar)(unsafe.Pointer(&out[0])), C.word32(outLen),
		key))
}

// Wc_RsaPrivateDecryptInline decrypts in using PKCS#1 v1.5 with the private key.
// wolfSSL writes the plaintext into in and returns a pointer into the in buffer;
// this wrapper copies the result into a new Go slice via C.GoBytes.
// Returns the plaintext as a slice on success, nil slice and negative int on error.
func Wc_RsaPrivateDecryptInline(in []byte, inLen int, key *C.struct_RsaKey) ([]byte, int) {
	if inLen < 0 || inLen > len(in) {
		return nil, BAD_FUNC_ARG
	}
	if len(in) == 0 {
		return nil, BAD_FUNC_ARG
	}
	var outPtr *C.uchar
	ret := int(C.go_wc_RsaPrivateDecryptInline(
		(*C.uchar)(unsafe.Pointer(&in[0])), C.word32(inLen),
		&outPtr, key))
	if ret < 0 {
		return nil, ret
	}
	if outPtr == nil {
		return nil, BAD_FUNC_ARG
	}
	return C.GoBytes(unsafe.Pointer(outPtr), C.int(ret)), ret
}

// Wc_RsaPublicEncrypt_ex encrypts in using the specified padding type, hash,
// and MGF algorithm. label may be nil (labelSz must be 0 in that case).
// outLen must be >= Wc_RsaEncryptSize(key). sz must be <= len(out).
// Requires wolfSSL built without HAVE_FIPS or with HAVE_FIPS_VERSION >= 2.
// Returns the number of bytes written to out on success, negative on error.
func Wc_RsaPublicEncrypt_ex(in []byte, inLen int, out []byte, outLen int, key *C.struct_RsaKey, rng *C.struct_WC_RNG, padType int, hash int, mgf int, label []byte, labelSz int) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if outLen < 0 || outLen > len(out) {
		return BAD_FUNC_ARG
	}
	if labelSz < 0 || labelSz > len(label) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 || len(out) == 0 {
		return BAD_FUNC_ARG
	}
	var labelPtr *C.uchar
	if labelSz > 0 {
		labelPtr = (*C.uchar)(unsafe.Pointer(&label[0]))
	}
	return int(C.go_wc_RsaPublicEncrypt_ex(
		(*C.uchar)(unsafe.Pointer(&in[0])), C.word32(inLen),
		(*C.uchar)(unsafe.Pointer(&out[0])), C.word32(outLen),
		key, rng,
		C.int(padType), C.enum_wc_HashType(hash), C.int(mgf),
		labelPtr, C.word32(labelSz)))
}

// Wc_RsaPrivateDecrypt_ex decrypts in using the specified padding type, hash,
// and MGF algorithm. label may be nil (labelSz must be 0 in that case).
// outLen must be >= the expected plaintext length. sz must be <= len(out).
// Requires wolfSSL built without HAVE_FIPS or with HAVE_FIPS_VERSION >= 2.
// Returns the number of plaintext bytes written to out on success, negative on error.
func Wc_RsaPrivateDecrypt_ex(in []byte, inLen int, out []byte, outLen int, key *C.struct_RsaKey, padType int, hash int, mgf int, label []byte, labelSz int) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if outLen < 0 || outLen > len(out) {
		return BAD_FUNC_ARG
	}
	if labelSz < 0 || labelSz > len(label) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 || len(out) == 0 {
		return BAD_FUNC_ARG
	}
	var labelPtr *C.uchar
	if labelSz > 0 {
		labelPtr = (*C.uchar)(unsafe.Pointer(&label[0]))
	}
	return int(C.go_wc_RsaPrivateDecrypt_ex(
		(*C.uchar)(unsafe.Pointer(&in[0])), C.word32(inLen),
		(*C.uchar)(unsafe.Pointer(&out[0])), C.word32(outLen),
		key,
		C.int(padType), C.enum_wc_HashType(hash), C.int(mgf),
		labelPtr, C.word32(labelSz)))
}

// Wc_RsaSSL_Sign signs in using PKCS#1 v1.5 raw (no hash OID prefix) with the
// private key. outLen must be >= Wc_RsaEncryptSize(key).
// Returns the number of bytes written to out on success, negative on error.
func Wc_RsaSSL_Sign(in []byte, inLen int, out []byte, outLen int, key *C.struct_RsaKey, rng *C.struct_WC_RNG) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if outLen < 0 || outLen > len(out) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 || len(out) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_RsaSSL_Sign(
		(*C.uchar)(unsafe.Pointer(&in[0])), C.word32(inLen),
		(*C.uchar)(unsafe.Pointer(&out[0])), C.word32(outLen),
		key, rng))
}

// Wc_RsaSSL_Verify recovers the original message from a PKCS#1 v1.5 signature
// using the public key. outLen must be >= Wc_RsaEncryptSize(key).
// Returns the number of bytes written to out on success, negative on error.
func Wc_RsaSSL_Verify(in []byte, inLen int, out []byte, outLen int, key *C.struct_RsaKey) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if outLen < 0 || outLen > len(out) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 || len(out) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_RsaSSL_Verify(
		(*C.uchar)(unsafe.Pointer(&in[0])), C.word32(inLen),
		(*C.uchar)(unsafe.Pointer(&out[0])), C.word32(outLen),
		key))
}

// Wc_RsaPSS_Sign signs in using RSA-PSS with the given hash and MGF algorithm.
// outLen must be >= Wc_RsaEncryptSize(key).
// Requires wolfSSL built with WC_RSA_PSS.
// Returns the number of bytes written to out on success, negative on error.
func Wc_RsaPSS_Sign(in []byte, inLen int, out []byte, outLen int, hash int, mgf int, key *C.struct_RsaKey, rng *C.struct_WC_RNG) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if outLen < 0 || outLen > len(out) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 || len(out) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_RsaPSS_Sign(
		(*C.uchar)(unsafe.Pointer(&in[0])), C.word32(inLen),
		(*C.uchar)(unsafe.Pointer(&out[0])), C.word32(outLen),
		C.enum_wc_HashType(hash), C.int(mgf),
		key, rng))
}

// Wc_RsaPSS_Sign_ex signs in using RSA-PSS with an explicit salt length.
// Pass -1 for saltLen to use the hash output length (recommended default).
// outLen must be >= Wc_RsaEncryptSize(key).
// Requires wolfSSL built with WC_RSA_PSS.
// Returns the number of bytes written to out on success, negative on error.
func Wc_RsaPSS_Sign_ex(in []byte, inLen int, out []byte, outLen int, hash int, mgf int, saltLen int, key *C.struct_RsaKey, rng *C.struct_WC_RNG) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if outLen < 0 || outLen > len(out) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 || len(out) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_RsaPSS_Sign_ex(
		(*C.uchar)(unsafe.Pointer(&in[0])), C.word32(inLen),
		(*C.uchar)(unsafe.Pointer(&out[0])), C.word32(outLen),
		C.enum_wc_HashType(hash), C.int(mgf), C.int(saltLen),
		key, rng))
}

// Wc_RsaPSS_Verify verifies an RSA-PSS signature and writes the recovered
// salt/message to out. outLen must be >= Wc_RsaEncryptSize(key).
// Requires wolfSSL built with WC_RSA_PSS.
// Returns the number of bytes written to out on success, negative on error.
func Wc_RsaPSS_Verify(in []byte, inLen int, out []byte, outLen int, hash int, mgf int, key *C.struct_RsaKey) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if outLen < 0 || outLen > len(out) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 || len(out) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_RsaPSS_Verify(
		(*C.uchar)(unsafe.Pointer(&in[0])), C.word32(inLen),
		(*C.uchar)(unsafe.Pointer(&out[0])), C.word32(outLen),
		C.enum_wc_HashType(hash), C.int(mgf),
		key))
}

// Wc_RsaPSS_Verify_ex verifies an RSA-PSS signature with an explicit salt
// length. Pass -1 for saltLen to use the hash output length.
// outLen must be >= Wc_RsaEncryptSize(key).
// Requires wolfSSL built with WC_RSA_PSS.
// Returns the number of bytes written to out on success, negative on error.
func Wc_RsaPSS_Verify_ex(in []byte, inLen int, out []byte, outLen int, hash int, mgf int, saltLen int, key *C.struct_RsaKey) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if outLen < 0 || outLen > len(out) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 || len(out) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_RsaPSS_Verify_ex(
		(*C.uchar)(unsafe.Pointer(&in[0])), C.word32(inLen),
		(*C.uchar)(unsafe.Pointer(&out[0])), C.word32(outLen),
		C.enum_wc_HashType(hash), C.int(mgf), C.int(saltLen),
		key))
}

// Wc_RsaPrivateKeyDecode decodes a DER-encoded PKCS#8/PKCS#1 private key into
// key. inOutIdx is both an input (byte offset to start parsing) and output
// (updated to next unparsed byte). inSz is the number of valid bytes in input.
// Requires wolfSSL built without HAVE_FIPS or with HAVE_FIPS_VERSION >= 2.
// Returns 0 on success, negative on error.
func Wc_RsaPrivateKeyDecode(input []byte, inOutIdx *int, key *C.struct_RsaKey, inSz int) int {
	if inSz < 0 || inSz > len(input) {
		return BAD_FUNC_ARG
	}
	if inOutIdx == nil {
		return BAD_FUNC_ARG
	}
	if len(input) == 0 {
		return BAD_FUNC_ARG
	}
	idx := C.word32(*inOutIdx)
	ret := int(C.go_wc_RsaPrivateKeyDecode(
		(*C.uchar)(unsafe.Pointer(&input[0])), &idx,
		key, C.word32(inSz)))
	*inOutIdx = int(idx)
	return ret
}

// Wc_RsaPublicKeyDecode decodes a DER-encoded SubjectPublicKeyInfo or PKCS#1
// public key into key. inOutIdx is both an input (byte offset to start
// parsing) and output (updated to next unparsed byte). inSz is the number of
// valid bytes in input.
// Requires wolfSSL built without HAVE_FIPS or with HAVE_FIPS_VERSION >= 2.
// Returns 0 on success, negative on error.
func Wc_RsaPublicKeyDecode(input []byte, inOutIdx *int, key *C.struct_RsaKey, inSz int) int {
	if inSz < 0 || inSz > len(input) {
		return BAD_FUNC_ARG
	}
	if inOutIdx == nil {
		return BAD_FUNC_ARG
	}
	if len(input) == 0 {
		return BAD_FUNC_ARG
	}
	idx := C.word32(*inOutIdx)
	ret := int(C.go_wc_RsaPublicKeyDecode(
		(*C.uchar)(unsafe.Pointer(&input[0])), &idx,
		key, C.word32(inSz)))
	*inOutIdx = int(idx)
	return ret
}

// Wc_RsaPublicKeyDecodeRaw initializes key from raw big-endian modulus n and
// public exponent e. nSz and eSz must be <= len(n) and len(e) respectively.
// Requires wolfSSL built without HAVE_FIPS or with HAVE_FIPS_VERSION >= 2.
// Returns 0 on success, negative on error.
func Wc_RsaPublicKeyDecodeRaw(n []byte, nSz int, e []byte, eSz int, key *C.struct_RsaKey) int {
	if nSz < 0 || nSz > len(n) {
		return BAD_FUNC_ARG
	}
	if eSz < 0 || eSz > len(e) {
		return BAD_FUNC_ARG
	}
	if len(n) == 0 || len(e) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_RsaPublicKeyDecodeRaw(
		(*C.uchar)(unsafe.Pointer(&n[0])), C.word32(nSz),
		(*C.uchar)(unsafe.Pointer(&e[0])), C.word32(eSz),
		key))
}

// Wc_RsaFlattenPublicKey extracts the public exponent e and modulus n from key
// into caller-supplied buffers. eSz and nSz are in/out: on input they hold the
// buffer capacities; on output (ret==0) they hold the actual byte lengths.
// Requires wolfSSL built without HAVE_FIPS or with HAVE_FIPS_VERSION >= 2.
// Returns 0 on success, negative on error.
func Wc_RsaFlattenPublicKey(key *C.struct_RsaKey, e []byte, eSz *int, n []byte, nSz *int) int {
	if eSz == nil || nSz == nil {
		return BAD_FUNC_ARG
	}
	if *eSz < 0 || *eSz > len(e) {
		return BAD_FUNC_ARG
	}
	if *nSz < 0 || *nSz > len(n) {
		return BAD_FUNC_ARG
	}
	if len(e) == 0 || len(n) == 0 {
		return BAD_FUNC_ARG
	}
	cESz := C.word32(*eSz)
	cNSz := C.word32(*nSz)
	ret := int(C.go_wc_RsaFlattenPublicKey(
		key,
		(*C.uchar)(unsafe.Pointer(&e[0])), &cESz,
		(*C.uchar)(unsafe.Pointer(&n[0])), &cNSz))
	if ret == 0 {
		*eSz = int(cESz)
		*nSz = int(cNSz)
	}
	return ret
}
