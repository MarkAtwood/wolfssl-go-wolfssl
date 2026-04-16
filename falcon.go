/* falcon.go
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
// #include <wolfssl/wolfcrypt/falcon.h>
// #include <wolfssl/wolfcrypt/random.h>
//
// /* falcon_key fields reference FALCON_MAX_PUB_KEY_SIZE etc. which are
//  * only defined when HAVE_PQC && HAVE_FALCON && HAVE_LIBOQS.  Provide an
//  * opaque stub struct when any of those guards are absent so the Go type
//  * alias still compiles. */
// #if !defined(HAVE_PQC) || !defined(HAVE_FALCON)
// typedef struct falcon_key {} falcon_key;
// #endif
//
// /* --- Init / Free --- */
//
// static int go_wc_falcon_init(falcon_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_FALCON)
//     return wc_falcon_init(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_falcon_init_ex(falcon_key* key, void* heap, int devId) {
// #if defined(HAVE_PQC) && defined(HAVE_FALCON)
//     return wc_falcon_init_ex(key, heap, devId);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_falcon_set_level(falcon_key* key, byte level) {
// #if defined(HAVE_PQC) && defined(HAVE_FALCON)
//     return wc_falcon_set_level(key, level);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_falcon_get_level(falcon_key* key, byte* level) {
// #if defined(HAVE_PQC) && defined(HAVE_FALCON)
//     return wc_falcon_get_level(key, level);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static void go_wc_falcon_free(falcon_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_FALCON)
//     wc_falcon_free(key);
// #endif
// }
//
// /* --- Sign --- */
//
// static int go_wc_falcon_sign_msg(const byte* in, word32 inLen, byte* out,
//                                   word32* outLen, falcon_key* key,
//                                   WC_RNG* rng) {
// #if defined(HAVE_PQC) && defined(HAVE_FALCON)
//     return wc_falcon_sign_msg(in, inLen, out, outLen, key, rng);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Verify --- */
//
// static int go_wc_falcon_verify_msg(const byte* sig, word32 sigLen,
//                                     const byte* msg, word32 msgLen,
//                                     int* res, falcon_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_FALCON)
//     return wc_falcon_verify_msg(sig, sigLen, msg, msgLen, res, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Key import --- */
//
// static int go_wc_falcon_import_public(const byte* in, word32 inLen,
//                                        falcon_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_FALCON)
//     return wc_falcon_import_public(in, inLen, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_falcon_import_private_only(const byte* priv, word32 privSz,
//                                              falcon_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_FALCON)
//     return wc_falcon_import_private_only(priv, privSz, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_falcon_import_private_key(const byte* priv, word32 privSz,
//                                             const byte* pub, word32 pubSz,
//                                             falcon_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_FALCON)
//     return wc_falcon_import_private_key(priv, privSz, pub, pubSz, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Key export --- */
//
// static int go_wc_falcon_export_public(falcon_key* key, byte* out,
//                                        word32* outLen) {
// #if defined(HAVE_PQC) && defined(HAVE_FALCON)
//     return wc_falcon_export_public(key, out, outLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_falcon_export_private_only(falcon_key* key, byte* out,
//                                              word32* outLen) {
// #if defined(HAVE_PQC) && defined(HAVE_FALCON)
//     return wc_falcon_export_private_only(key, out, outLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_falcon_export_key(falcon_key* key, byte* priv,
//                                     word32* privSz, byte* pub,
//                                     word32* pubSz) {
// #if defined(HAVE_PQC) && defined(HAVE_FALCON)
//     return wc_falcon_export_key(key, priv, privSz, pub, pubSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Size queries --- */
//
// static int go_wc_falcon_size(falcon_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_FALCON)
//     return wc_falcon_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_falcon_priv_size(falcon_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_FALCON)
//     return wc_falcon_priv_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_falcon_pub_size(falcon_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_FALCON)
//     return wc_falcon_pub_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_falcon_sig_size(falcon_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_FALCON)
//     return wc_falcon_sig_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
import "C"
import "unsafe"

// FalconKey is a type alias for the wolfSSL falcon_key struct.
// falcon_key structs are NOT thread-safe; callers must not share a key
// across goroutines without external synchronization.
type FalconKey = C.struct_falcon_key

// Wc_FalconInit initializes a falcon_key struct.
// Returns 0 on success, negative on error.
func Wc_FalconInit(key *C.struct_falcon_key) int {
	return int(C.go_wc_falcon_init(key))
}

// Wc_FalconInitEx initializes a falcon_key struct with a heap hint and device ID.
// Returns 0 on success, negative on error.
func Wc_FalconInitEx(key *C.struct_falcon_key, heap unsafe.Pointer, devId int) int {
	return int(C.go_wc_falcon_init_ex(key, heap, C.int(devId)))
}

// Wc_FalconSetLevel sets the security level for key (1 = Falcon-512, 5 = Falcon-1024).
// Must be called after Init and before MakeKey or any import.
// Returns 0 on success, negative on error.
func Wc_FalconSetLevel(key *C.struct_falcon_key, level byte) int {
	return int(C.go_wc_falcon_set_level(key, C.byte(level)))
}

// Wc_FalconGetLevel retrieves the security level currently set for key.
// Returns 0 on success, negative on error.
func Wc_FalconGetLevel(key *C.struct_falcon_key, level *byte) int {
	if level == nil {
		return BAD_FUNC_ARG
	}
	cLevel := C.byte(0)
	ret := int(C.go_wc_falcon_get_level(key, &cLevel))
	if ret == 0 {
		*level = byte(cLevel)
	}
	return ret
}

// Wc_FalconFree releases resources associated with a falcon_key struct.
func Wc_FalconFree(key *C.struct_falcon_key) {
	C.go_wc_falcon_free(key)
}

// Wc_FalconSignMsg signs msg with key, writing the signature into out.
// outLen is updated to the actual signature length on success.
// Returns 0 on success, negative on error.
func Wc_FalconSignMsg(in []byte, inLen int, out []byte, outLen *int, key *C.struct_falcon_key, rng *C.struct_WC_RNG) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if outLen == nil || len(out) == 0 {
		return BAD_FUNC_ARG
	}
	var inPtr *C.byte
	if len(in) > 0 {
		inPtr = (*C.byte)(unsafe.Pointer(&in[0]))
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_falcon_sign_msg(
		inPtr, C.word32(inLen),
		(*C.byte)(unsafe.Pointer(&out[0])), &cOutLen,
		key, rng))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_FalconVerifyMsg verifies sig against msg using key.
// res is set to 1 on valid signature, 0 on invalid.
// Returns 0 on success (check res for validity), negative on error.
func Wc_FalconVerifyMsg(sig []byte, sigLen int, msg []byte, msgLen int, res *int, key *C.struct_falcon_key) int {
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
	cRes := C.int(0)
	ret := int(C.go_wc_falcon_verify_msg(
		(*C.byte)(unsafe.Pointer(&sig[0])), C.word32(sigLen),
		msgPtr, C.word32(msgLen),
		&cRes, key))
	if ret == 0 {
		*res = int(cRes)
	}
	return ret
}

// Wc_FalconImportPublic imports a raw public key into key.
// inLen must be <= len(in).
// Returns 0 on success, negative on error.
func Wc_FalconImportPublic(in []byte, inLen int, key *C.struct_falcon_key) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_falcon_import_public((*C.byte)(unsafe.Pointer(&in[0])), C.word32(inLen), key))
}

// Wc_FalconImportPrivateOnly imports only the private key into key.
// privSz must be <= len(priv).
// Returns 0 on success, negative on error.
func Wc_FalconImportPrivateOnly(priv []byte, privSz int, key *C.struct_falcon_key) int {
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if len(priv) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_falcon_import_private_only((*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz), key))
}

// Wc_FalconImportPrivateKey imports both the private and public key into key.
// privSz must be <= len(priv); pubSz must be <= len(pub).
// Returns 0 on success, negative on error.
func Wc_FalconImportPrivateKey(priv []byte, privSz int, pub []byte, pubSz int, key *C.struct_falcon_key) int {
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if pubSz < 0 || pubSz > len(pub) {
		return BAD_FUNC_ARG
	}
	if len(priv) == 0 || len(pub) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_falcon_import_private_key(
		(*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz),
		(*C.byte)(unsafe.Pointer(&pub[0])), C.word32(pubSz),
		key))
}

// Wc_FalconExportPublic exports the public key from key into out.
// outLen is updated to the actual number of bytes written on success.
// Returns 0 on success, negative on error.
func Wc_FalconExportPublic(key *C.struct_falcon_key, out []byte, outLen *int) int {
	if outLen == nil || len(out) == 0 {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_falcon_export_public(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_FalconExportPrivateOnly exports only the private key from key into out.
// outLen is updated to the actual number of bytes written on success.
// Returns 0 on success, negative on error.
func Wc_FalconExportPrivateOnly(key *C.struct_falcon_key, out []byte, outLen *int) int {
	if outLen == nil || len(out) == 0 {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_falcon_export_private_only(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_FalconExportKey exports both the private and public key from key.
// privSz and pubSz are updated to the actual byte counts on success.
// Returns 0 on success, negative on error.
func Wc_FalconExportKey(key *C.struct_falcon_key, priv []byte, privSz *int, pub []byte, pubSz *int) int {
	if privSz == nil || len(priv) == 0 {
		return BAD_FUNC_ARG
	}
	if pubSz == nil || len(pub) == 0 {
		return BAD_FUNC_ARG
	}
	cPrivSz := C.word32(len(priv))
	cPubSz := C.word32(len(pub))
	ret := int(C.go_wc_falcon_export_key(key,
		(*C.byte)(unsafe.Pointer(&priv[0])), &cPrivSz,
		(*C.byte)(unsafe.Pointer(&pub[0])), &cPubSz))
	if ret == 0 {
		*privSz = int(cPrivSz)
		*pubSz = int(cPubSz)
	}
	return ret
}

// Wc_FalconSize returns the private key size for key's configured level.
// Returns the size in bytes, or negative on error.
func Wc_FalconSize(key *C.struct_falcon_key) int {
	return int(C.go_wc_falcon_size(key))
}

// Wc_FalconPrivSize returns the full private key size for key's configured level.
// Returns the size in bytes, or negative on error.
func Wc_FalconPrivSize(key *C.struct_falcon_key) int {
	return int(C.go_wc_falcon_priv_size(key))
}

// Wc_FalconPubSize returns the public key size for key's configured level.
// Returns the size in bytes, or negative on error.
func Wc_FalconPubSize(key *C.struct_falcon_key) int {
	return int(C.go_wc_falcon_pub_size(key))
}

// Wc_FalconSigSize returns the signature size for key's configured level.
// Returns the size in bytes, or negative on error.
func Wc_FalconSigSize(key *C.struct_falcon_key) int {
	return int(C.go_wc_falcon_sig_size(key))
}
