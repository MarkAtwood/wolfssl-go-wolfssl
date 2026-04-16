/* kyber.go
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

package wolfSSL

// #cgo CFLAGS: -I/usr/include -I/usr/include/wolfssl -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/error-crypt.h>
// #include <wolfssl/wolfcrypt/mlkem.h>
// #include <wolfssl/wolfcrypt/random.h>
//
// #ifndef WOLFSSL_HAVE_MLKEM
// /* Provide a stub struct so the Go type alias compiles without the real body. */
// typedef struct MlKemKey {} MlKemKey;
// #endif
//
// /* Key type constants (duplicated as plain C enums for stub builds). */
// enum {
//     GO_WC_ML_KEM_512  = 0,
//     GO_WC_ML_KEM_768  = 1,
//     GO_WC_ML_KEM_1024 = 2
// };
//
// /* --- Init / Free --- */
//
// static int go_wc_MlKemKey_Init(MlKemKey* key, int type, void* heap, int devId) {
// #ifdef WOLFSSL_HAVE_MLKEM
//     return wc_MlKemKey_Init(key, type, heap, devId);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_MlKemKey_Free(MlKemKey* key) {
// #ifdef WOLFSSL_HAVE_MLKEM
//     return wc_MlKemKey_Free(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Key generation --- */
//
// static int go_wc_MlKemKey_MakeKey(MlKemKey* key, WC_RNG* rng) {
// #ifdef WOLFSSL_HAVE_MLKEM
//     return wc_MlKemKey_MakeKey(key, rng);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Size queries --- */
//
// static int go_wc_MlKemKey_CipherTextSize(MlKemKey* key, word32* len) {
// #ifdef WOLFSSL_HAVE_MLKEM
//     return wc_MlKemKey_CipherTextSize(key, len);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_MlKemKey_SharedSecretSize(MlKemKey* key, word32* len) {
// #ifdef WOLFSSL_HAVE_MLKEM
//     return wc_MlKemKey_SharedSecretSize(key, len);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_MlKemKey_PublicKeySize(MlKemKey* key, word32* len) {
// #ifdef WOLFSSL_HAVE_MLKEM
//     return wc_MlKemKey_PublicKeySize(key, len);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_MlKemKey_PrivateKeySize(MlKemKey* key, word32* len) {
// #ifdef WOLFSSL_HAVE_MLKEM
//     return wc_MlKemKey_PrivateKeySize(key, len);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Encapsulate / Decapsulate --- */
//
// static int go_wc_MlKemKey_Encapsulate(MlKemKey* key, unsigned char* ct,
//                                        unsigned char* ss, WC_RNG* rng) {
// #ifdef WOLFSSL_HAVE_MLKEM
//     return wc_MlKemKey_Encapsulate(key, ct, ss, rng);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_MlKemKey_Decapsulate(MlKemKey* key, unsigned char* ss,
//                                        const unsigned char* ct, word32 len) {
// #ifdef WOLFSSL_HAVE_MLKEM
//     return wc_MlKemKey_Decapsulate(key, ss, ct, len);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Key encode / decode --- */
//
// static int go_wc_MlKemKey_EncodePublicKey(MlKemKey* key, unsigned char* out,
//                                            word32 len) {
// #ifdef WOLFSSL_HAVE_MLKEM
//     return wc_MlKemKey_EncodePublicKey(key, out, len);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_MlKemKey_EncodePrivateKey(MlKemKey* key, unsigned char* out,
//                                             word32 len) {
// #ifdef WOLFSSL_HAVE_MLKEM
//     return wc_MlKemKey_EncodePrivateKey(key, out, len);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_MlKemKey_DecodePublicKey(MlKemKey* key,
//                                            const unsigned char* in,
//                                            word32 len) {
// #ifdef WOLFSSL_HAVE_MLKEM
//     return wc_MlKemKey_DecodePublicKey(key, in, len);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_MlKemKey_DecodePrivateKey(MlKemKey* key,
//                                             const unsigned char* in,
//                                             word32 len) {
// #ifdef WOLFSSL_HAVE_MLKEM
//     return wc_MlKemKey_DecodePrivateKey(key, in, len);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
import "C"
import "unsafe"

// MlKemKey is a type alias for the wolfSSL MlKemKey struct (ML-KEM / Kyber).
// MlKemKey structs are NOT thread-safe; callers must not share a key
// across goroutines without external synchronization.
type MlKemKey = C.MlKemKey

// ML-KEM key type constants.
const (
	WC_ML_KEM_512  = int(C.GO_WC_ML_KEM_512)
	WC_ML_KEM_768  = int(C.GO_WC_ML_KEM_768)
	WC_ML_KEM_1024 = int(C.GO_WC_ML_KEM_1024)
)

// Wc_MlKemKey_Init initializes an MlKemKey struct for the given key type.
// type must be one of WC_ML_KEM_512, WC_ML_KEM_768, or WC_ML_KEM_1024.
// Returns 0 on success, negative on error.
func Wc_MlKemKey_Init(key *C.MlKemKey, keyType int, heap unsafe.Pointer, devId int) int {
	return int(C.go_wc_MlKemKey_Init(key, C.int(keyType), heap, C.int(devId)))
}

// Wc_MlKemKey_Free releases resources associated with an MlKemKey struct.
// Returns 0 on success, negative on error.
func Wc_MlKemKey_Free(key *C.MlKemKey) int {
	return int(C.go_wc_MlKemKey_Free(key))
}

// Wc_MlKemKey_MakeKey generates a new ML-KEM key pair into key.
// Returns 0 on success, negative on error.
func Wc_MlKemKey_MakeKey(key *C.MlKemKey, rng *C.struct_WC_RNG) int {
	return int(C.go_wc_MlKemKey_MakeKey(key, rng))
}

// Wc_MlKemKey_CipherTextSize returns the cipher text size for key's type into len.
// Returns 0 on success, negative on error.
func Wc_MlKemKey_CipherTextSize(key *C.MlKemKey, length *int) int {
	if length == nil {
		return BAD_FUNC_ARG
	}
	cLen := C.word32(0)
	ret := int(C.go_wc_MlKemKey_CipherTextSize(key, &cLen))
	if ret == 0 {
		*length = int(cLen)
	}
	return ret
}

// Wc_MlKemKey_SharedSecretSize returns the shared secret size for key's type into len.
// Returns 0 on success, negative on error.
func Wc_MlKemKey_SharedSecretSize(key *C.MlKemKey, length *int) int {
	if length == nil {
		return BAD_FUNC_ARG
	}
	cLen := C.word32(0)
	ret := int(C.go_wc_MlKemKey_SharedSecretSize(key, &cLen))
	if ret == 0 {
		*length = int(cLen)
	}
	return ret
}

// Wc_MlKemKey_PublicKeySize returns the encoded public key size for key's type into len.
// Returns 0 on success, negative on error.
func Wc_MlKemKey_PublicKeySize(key *C.MlKemKey, length *int) int {
	if length == nil {
		return BAD_FUNC_ARG
	}
	cLen := C.word32(0)
	ret := int(C.go_wc_MlKemKey_PublicKeySize(key, &cLen))
	if ret == 0 {
		*length = int(cLen)
	}
	return ret
}

// Wc_MlKemKey_PrivateKeySize returns the encoded private key size for key's type into len.
// Returns 0 on success, negative on error.
func Wc_MlKemKey_PrivateKeySize(key *C.MlKemKey, length *int) int {
	if length == nil {
		return BAD_FUNC_ARG
	}
	cLen := C.word32(0)
	ret := int(C.go_wc_MlKemKey_PrivateKeySize(key, &cLen))
	if ret == 0 {
		*length = int(cLen)
	}
	return ret
}

// Wc_MlKemKey_Encapsulate generates a cipher text ct and shared secret ss
// using the public key in key.
// ct must be at least CipherTextSize bytes; ss must be at least SharedSecretSize bytes.
// Returns 0 on success, negative on error.
func Wc_MlKemKey_Encapsulate(key *C.MlKemKey, ct []byte, ss []byte, rng *C.struct_WC_RNG) int {
	if len(ct) == 0 || len(ss) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_MlKemKey_Encapsulate(key,
		(*C.uchar)(unsafe.Pointer(&ct[0])),
		(*C.uchar)(unsafe.Pointer(&ss[0])),
		rng))
}

// Wc_MlKemKey_Decapsulate recovers the shared secret ss from cipher text ct
// using the private key in key.
// ss must be at least SharedSecretSize bytes; ctLen must be <= len(ct).
// Returns 0 on success, negative on error.
func Wc_MlKemKey_Decapsulate(key *C.MlKemKey, ss []byte, ct []byte, ctLen int) int {
	if ctLen < 0 || ctLen > len(ct) {
		return BAD_FUNC_ARG
	}
	if len(ss) == 0 || len(ct) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_MlKemKey_Decapsulate(key,
		(*C.uchar)(unsafe.Pointer(&ss[0])),
		(*C.uchar)(unsafe.Pointer(&ct[0])),
		C.word32(ctLen)))
}

// Wc_MlKemKey_EncodePublicKey encodes the public key from key into out.
// out must be exactly PublicKeySize bytes.
// Returns 0 on success, negative on error.
func Wc_MlKemKey_EncodePublicKey(key *C.MlKemKey, out []byte) int {
	if len(out) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_MlKemKey_EncodePublicKey(key,
		(*C.uchar)(unsafe.Pointer(&out[0])),
		C.word32(len(out))))
}

// Wc_MlKemKey_EncodePrivateKey encodes the private key from key into out.
// out must be exactly PrivateKeySize bytes.
// Returns 0 on success, negative on error.
func Wc_MlKemKey_EncodePrivateKey(key *C.MlKemKey, out []byte) int {
	if len(out) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_MlKemKey_EncodePrivateKey(key,
		(*C.uchar)(unsafe.Pointer(&out[0])),
		C.word32(len(out))))
}

// Wc_MlKemKey_DecodePublicKey decodes a raw public key from in into key.
// len must be <= len(in).
// Returns 0 on success, negative on error.
func Wc_MlKemKey_DecodePublicKey(key *C.MlKemKey, in []byte, length int) int {
	if length < 0 || length > len(in) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_MlKemKey_DecodePublicKey(key,
		(*C.uchar)(unsafe.Pointer(&in[0])),
		C.word32(length)))
}

// Wc_MlKemKey_DecodePrivateKey decodes a raw private key from in into key.
// len must be <= len(in).
// Returns 0 on success, negative on error.
func Wc_MlKemKey_DecodePrivateKey(key *C.MlKemKey, in []byte, length int) int {
	if length < 0 || length > len(in) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_MlKemKey_DecodePrivateKey(key,
		(*C.uchar)(unsafe.Pointer(&in[0])),
		C.word32(length)))
}
