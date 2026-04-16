/* dilithium.go
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
// #include <wolfssl/wolfcrypt/dilithium.h>
// #include <wolfssl/wolfcrypt/random.h>
//
// #ifndef HAVE_DILITHIUM
// typedef struct dilithium_key {} dilithium_key;
// #endif
//
// /* --- Init / Free --- */
//
// static int go_wc_dilithium_init(dilithium_key* key) {
// #ifdef HAVE_DILITHIUM
//     return wc_dilithium_init(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_dilithium_init_ex(dilithium_key* key, void* heap, int devId) {
// #ifdef HAVE_DILITHIUM
//     return wc_dilithium_init_ex(key, heap, devId);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_dilithium_set_level(dilithium_key* key, byte level) {
// #ifdef HAVE_DILITHIUM
//     return wc_dilithium_set_level(key, level);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_dilithium_get_level(dilithium_key* key, byte* level) {
// #ifdef HAVE_DILITHIUM
//     return wc_dilithium_get_level(key, level);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static void go_wc_dilithium_free(dilithium_key* key) {
// #ifdef HAVE_DILITHIUM
//     wc_dilithium_free(key);
// #endif
// }
//
// /* --- Key generation --- */
//
// static int go_wc_dilithium_make_key(dilithium_key* key, WC_RNG* rng) {
// #if defined(HAVE_DILITHIUM) && !defined(WOLFSSL_DILITHIUM_VERIFY_ONLY)
//     return wc_dilithium_make_key(key, rng);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Sign --- */
//
// static int go_wc_dilithium_sign_ctx_msg(const byte* ctx, byte ctxLen,
//                                         const byte* msg, word32 msgLen,
//                                         byte* sig, word32* sigLen,
//                                         dilithium_key* key, WC_RNG* rng) {
// #if defined(HAVE_DILITHIUM) && !defined(WOLFSSL_DILITHIUM_VERIFY_ONLY)
//     return wc_dilithium_sign_ctx_msg(ctx, ctxLen, msg, msgLen, sig, sigLen, key, rng);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Verify --- */
//
// static int go_wc_dilithium_verify_ctx_msg(const byte* sig, word32 sigLen,
//                                           const byte* ctx, byte ctxLen,
//                                           const byte* msg, word32 msgLen,
//                                           int* res, dilithium_key* key) {
// #ifdef HAVE_DILITHIUM
//     return wc_dilithium_verify_ctx_msg(sig, sigLen, ctx, ctxLen, msg, msgLen, res, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Key import --- */
//
// static int go_wc_dilithium_import_public(const byte* in, word32 inLen,
//                                          dilithium_key* key) {
// #ifdef HAVE_DILITHIUM
//     return wc_dilithium_import_public(in, inLen, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_dilithium_import_private(const byte* priv, word32 privSz,
//                                           dilithium_key* key) {
// #if defined(HAVE_DILITHIUM) && !defined(WOLFSSL_DILITHIUM_VERIFY_ONLY)
//     return wc_dilithium_import_private(priv, privSz, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_dilithium_import_key(const byte* priv, word32 privSz,
//                                       const byte* pub, word32 pubSz,
//                                       dilithium_key* key) {
// #if defined(HAVE_DILITHIUM) && !defined(WOLFSSL_DILITHIUM_VERIFY_ONLY)
//     return wc_dilithium_import_key(priv, privSz, pub, pubSz, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Key export --- */
//
// static int go_wc_dilithium_export_public(dilithium_key* key, byte* out,
//                                          word32* outLen) {
// #ifdef HAVE_DILITHIUM
//     return wc_dilithium_export_public(key, out, outLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_dilithium_export_private(dilithium_key* key, byte* out,
//                                           word32* outLen) {
// #if defined(HAVE_DILITHIUM) && !defined(WOLFSSL_DILITHIUM_VERIFY_ONLY)
//     return wc_dilithium_export_private(key, out, outLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_dilithium_export_key(dilithium_key* key,
//                                       byte* priv, word32* privSz,
//                                       byte* pub, word32* pubSz) {
// #if defined(HAVE_DILITHIUM) && !defined(WOLFSSL_DILITHIUM_VERIFY_ONLY)
//     return wc_dilithium_export_key(key, priv, privSz, pub, pubSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Size queries --- */
//
// static int go_wc_dilithium_size(dilithium_key* key) {
// #ifdef HAVE_DILITHIUM
//     return wc_dilithium_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_dilithium_priv_size(dilithium_key* key) {
// #ifdef HAVE_DILITHIUM
//     return wc_dilithium_priv_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_dilithium_pub_size(dilithium_key* key) {
// #ifdef HAVE_DILITHIUM
//     return wc_dilithium_pub_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_dilithium_sig_size(dilithium_key* key) {
// #ifdef HAVE_DILITHIUM
//     return wc_dilithium_sig_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
import "C"
import "unsafe"

// DilithiumKey is a type alias for the wolfSSL dilithium_key struct (ML-DSA).
// dilithium_key structs are NOT thread-safe; callers must not share a key
// across goroutines without external synchronization.
type DilithiumKey = C.struct_dilithium_key

// Wc_DilithiumInit initializes a dilithium_key struct.
// Returns 0 on success, negative on error.
func Wc_DilithiumInit(key *C.struct_dilithium_key) int {
	return int(C.go_wc_dilithium_init(key))
}

// Wc_DilithiumInitEx initializes a dilithium_key struct with a heap hint and device ID.
// Returns 0 on success, negative on error.
func Wc_DilithiumInitEx(key *C.struct_dilithium_key, heap unsafe.Pointer, devId int) int {
	return int(C.go_wc_dilithium_init_ex(key, heap, C.int(devId)))
}

// Wc_DilithiumSetLevel sets the security level for key (2 = ML-DSA-44, 3 = ML-DSA-65, 5 = ML-DSA-87).
// Must be called after Init and before MakeKey or any import.
// Returns 0 on success, negative on error.
func Wc_DilithiumSetLevel(key *C.struct_dilithium_key, level byte) int {
	return int(C.go_wc_dilithium_set_level(key, C.byte(level)))
}

// Wc_DilithiumGetLevel retrieves the security level currently set for key.
// Returns 0 on success, negative on error.
func Wc_DilithiumGetLevel(key *C.struct_dilithium_key, level *byte) int {
	if level == nil {
		return BAD_FUNC_ARG
	}
	cLevel := C.byte(0)
	ret := int(C.go_wc_dilithium_get_level(key, &cLevel))
	if ret == 0 {
		*level = byte(cLevel)
	}
	return ret
}

// Wc_DilithiumFree releases resources associated with a dilithium_key struct.
func Wc_DilithiumFree(key *C.struct_dilithium_key) {
	C.go_wc_dilithium_free(key)
}

// Wc_DilithiumMakeKey generates a new Dilithium/ML-DSA key pair.
// The security level must be set with Wc_DilithiumSetLevel before calling this.
// Returns 0 on success, negative on error.
func Wc_DilithiumMakeKey(key *C.struct_dilithium_key, rng *C.struct_WC_RNG) int {
	return int(C.go_wc_dilithium_make_key(key, rng))
}

// Wc_DilithiumSignCtxMsg signs msg using the ML-DSA context-based API.
// ctx may be nil when ctxLen is 0 (empty context, FIPS 204 compliant).
// sig must be large enough to hold the signature; sigLen is updated on success.
// Returns 0 on success, negative on error.
func Wc_DilithiumSignCtxMsg(key *C.struct_dilithium_key, ctx []byte, ctxLen byte,
	msg []byte, msgLen int, sig []byte, sigLen *int, rng *C.struct_WC_RNG) int {
	if msgLen < 0 || msgLen > len(msg) {
		return BAD_FUNC_ARG
	}
	if sigLen == nil || len(sig) == 0 {
		return BAD_FUNC_ARG
	}
	var msgPtr *C.byte
	if len(msg) > 0 {
		msgPtr = (*C.byte)(unsafe.Pointer(&msg[0]))
	}
	var ctxPtr *C.byte
	if ctxLen > 0 && len(ctx) > 0 {
		ctxPtr = (*C.byte)(unsafe.Pointer(&ctx[0]))
	}
	cSigLen := C.word32(len(sig))
	ret := int(C.go_wc_dilithium_sign_ctx_msg(
		ctxPtr, C.byte(ctxLen),
		msgPtr, C.word32(msgLen),
		(*C.byte)(unsafe.Pointer(&sig[0])), &cSigLen,
		key, rng))
	if ret == 0 {
		*sigLen = int(cSigLen)
	}
	return ret
}

// Wc_DilithiumVerifyCtxMsg verifies sig against msg using the ML-DSA context-based API.
// ctx may be nil when ctxLen is 0 (empty context, FIPS 204 compliant).
// res is set to 1 on valid signature, 0 on invalid.
// Returns 0 on success (check res for validity), negative on error.
func Wc_DilithiumVerifyCtxMsg(sig []byte, sigLen int, ctx []byte, ctxLen byte,
	msg []byte, msgLen int, res *int, key *C.struct_dilithium_key) int {
	if sigLen < 0 || sigLen > len(sig) {
		return BAD_FUNC_ARG
	}
	if msgLen < 0 || msgLen > len(msg) {
		return BAD_FUNC_ARG
	}
	if res == nil || len(sig) == 0 {
		return BAD_FUNC_ARG
	}
	var msgPtr *C.byte
	if len(msg) > 0 {
		msgPtr = (*C.byte)(unsafe.Pointer(&msg[0]))
	}
	var ctxPtr *C.byte
	if ctxLen > 0 && len(ctx) > 0 {
		ctxPtr = (*C.byte)(unsafe.Pointer(&ctx[0]))
	}
	cRes := C.int(0)
	ret := int(C.go_wc_dilithium_verify_ctx_msg(
		(*C.byte)(unsafe.Pointer(&sig[0])), C.word32(sigLen),
		ctxPtr, C.byte(ctxLen),
		msgPtr, C.word32(msgLen),
		&cRes, key))
	if ret == 0 {
		*res = int(cRes)
	}
	return ret
}

// Wc_DilithiumImportPublic imports a raw public key into key.
// inLen must be <= len(in).
// Returns 0 on success, negative on error.
func Wc_DilithiumImportPublic(in []byte, inLen int, key *C.struct_dilithium_key) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_dilithium_import_public((*C.byte)(unsafe.Pointer(&in[0])), C.word32(inLen), key))
}

// Wc_DilithiumImportPrivate imports a raw private key into key.
// privSz must be <= len(priv).
// Returns 0 on success, negative on error.
func Wc_DilithiumImportPrivate(priv []byte, privSz int, key *C.struct_dilithium_key) int {
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if len(priv) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_dilithium_import_private((*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz), key))
}

// Wc_DilithiumImportKey imports both private and public key material into key.
// privSz must be <= len(priv); pubSz must be <= len(pub).
// Returns 0 on success, negative on error.
func Wc_DilithiumImportKey(priv []byte, privSz int, pub []byte, pubSz int, key *C.struct_dilithium_key) int {
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if pubSz < 0 || pubSz > len(pub) {
		return BAD_FUNC_ARG
	}
	if len(priv) == 0 || len(pub) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_dilithium_import_key(
		(*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz),
		(*C.byte)(unsafe.Pointer(&pub[0])), C.word32(pubSz),
		key))
}

// Wc_DilithiumExportPublic exports the public key from key into out.
// outLen is updated to the actual number of bytes written on success.
// Returns 0 on success, negative on error.
func Wc_DilithiumExportPublic(key *C.struct_dilithium_key, out []byte, outLen *int) int {
	if outLen == nil || len(out) == 0 {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_dilithium_export_public(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_DilithiumExportPrivate exports the private key from key into out.
// outLen is updated to the actual number of bytes written on success.
// Returns 0 on success, negative on error.
func Wc_DilithiumExportPrivate(key *C.struct_dilithium_key, out []byte, outLen *int) int {
	if outLen == nil || len(out) == 0 {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_dilithium_export_private(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_DilithiumExportKey exports both private and public key material from key.
// privSz and pubSz are updated to the actual byte counts on success.
// Returns 0 on success, negative on error.
func Wc_DilithiumExportKey(key *C.struct_dilithium_key, priv []byte, privSz *int, pub []byte, pubSz *int) int {
	if privSz == nil || len(priv) == 0 {
		return BAD_FUNC_ARG
	}
	if pubSz == nil || len(pub) == 0 {
		return BAD_FUNC_ARG
	}
	cPrivSz := C.word32(len(priv))
	cPubSz := C.word32(len(pub))
	ret := int(C.go_wc_dilithium_export_key(key,
		(*C.byte)(unsafe.Pointer(&priv[0])), &cPrivSz,
		(*C.byte)(unsafe.Pointer(&pub[0])), &cPubSz))
	if ret == 0 {
		*privSz = int(cPrivSz)
		*pubSz = int(cPubSz)
	}
	return ret
}

// Wc_DilithiumSize returns the private key size for the configured level.
// Returns the size in bytes, or negative on error.
func Wc_DilithiumSize(key *C.struct_dilithium_key) int {
	return int(C.go_wc_dilithium_size(key))
}

// Wc_DilithiumPrivSize returns the full private key size for the configured level.
// Returns the size in bytes, or negative on error.
func Wc_DilithiumPrivSize(key *C.struct_dilithium_key) int {
	return int(C.go_wc_dilithium_priv_size(key))
}

// Wc_DilithiumPubSize returns the public key size for the configured level.
// Returns the size in bytes, or negative on error.
func Wc_DilithiumPubSize(key *C.struct_dilithium_key) int {
	return int(C.go_wc_dilithium_pub_size(key))
}

// Wc_DilithiumSigSize returns the signature size for the configured level.
// Returns the size in bytes, or negative on error.
func Wc_DilithiumSigSize(key *C.struct_dilithium_key) int {
	return int(C.go_wc_dilithium_sig_size(key))
}
