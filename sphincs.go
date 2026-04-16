/* sphincs.go
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
// #include <wolfssl/wolfcrypt/sphincs.h>
// #include <wolfssl/wolfcrypt/random.h>
//
// /* sphincs_key fields reference SPHINCS_MAX_PUB_KEY_SIZE etc. which are
//  * only defined when HAVE_PQC && HAVE_SPHINCS && HAVE_LIBOQS.  Provide an
//  * opaque stub struct when any of those guards are absent so the Go type
//  * alias still compiles. */
// #if !defined(HAVE_PQC) || !defined(HAVE_SPHINCS)
// typedef struct sphincs_key {} sphincs_key;
// #endif
//
// /* Variant constants (duplicated so they are always available). */
// enum {
//     GO_SPHINCS_FAST_VARIANT  = 1,
//     GO_SPHINCS_SMALL_VARIANT = 2
// };
//
// /* --- Init / Free --- */
//
// static int go_wc_sphincs_init(sphincs_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_SPHINCS)
//     return wc_sphincs_init(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_sphincs_set_level_and_optim(sphincs_key* key, byte level,
//                                               byte optim) {
// #if defined(HAVE_PQC) && defined(HAVE_SPHINCS)
//     return wc_sphincs_set_level_and_optim(key, level, optim);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_sphincs_get_level_and_optim(sphincs_key* key, byte* level,
//                                               byte* optim) {
// #if defined(HAVE_PQC) && defined(HAVE_SPHINCS)
//     return wc_sphincs_get_level_and_optim(key, level, optim);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static void go_wc_sphincs_free(sphincs_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_SPHINCS)
//     wc_sphincs_free(key);
// #endif
// }
//
// /* --- Sign --- */
//
// static int go_wc_sphincs_sign_msg(const byte* in, word32 inLen, byte* out,
//                                    word32* outLen, sphincs_key* key,
//                                    WC_RNG* rng) {
// #if defined(HAVE_PQC) && defined(HAVE_SPHINCS)
//     return wc_sphincs_sign_msg(in, inLen, out, outLen, key, rng);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Verify --- */
//
// static int go_wc_sphincs_verify_msg(const byte* sig, word32 sigLen,
//                                      const byte* msg, word32 msgLen,
//                                      int* res, sphincs_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_SPHINCS)
//     return wc_sphincs_verify_msg(sig, sigLen, msg, msgLen, res, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Key import --- */
//
// static int go_wc_sphincs_import_public(const byte* in, word32 inLen,
//                                         sphincs_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_SPHINCS)
//     return wc_sphincs_import_public(in, inLen, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_sphincs_import_private_only(const byte* priv, word32 privSz,
//                                               sphincs_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_SPHINCS)
//     return wc_sphincs_import_private_only(priv, privSz, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_sphincs_import_private_key(const byte* priv, word32 privSz,
//                                              const byte* pub, word32 pubSz,
//                                              sphincs_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_SPHINCS)
//     return wc_sphincs_import_private_key(priv, privSz, pub, pubSz, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Key export --- */
//
// static int go_wc_sphincs_export_public(sphincs_key* key, byte* out,
//                                         word32* outLen) {
// #if defined(HAVE_PQC) && defined(HAVE_SPHINCS)
//     return wc_sphincs_export_public(key, out, outLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_sphincs_export_private_only(sphincs_key* key, byte* out,
//                                               word32* outLen) {
// #if defined(HAVE_PQC) && defined(HAVE_SPHINCS)
//     return wc_sphincs_export_private_only(key, out, outLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_sphincs_export_key(sphincs_key* key, byte* priv,
//                                      word32* privSz, byte* pub,
//                                      word32* pubSz) {
// #if defined(HAVE_PQC) && defined(HAVE_SPHINCS)
//     return wc_sphincs_export_key(key, priv, privSz, pub, pubSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Size queries --- */
//
// static int go_wc_sphincs_size(sphincs_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_SPHINCS)
//     return wc_sphincs_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_sphincs_priv_size(sphincs_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_SPHINCS)
//     return wc_sphincs_priv_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_sphincs_pub_size(sphincs_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_SPHINCS)
//     return wc_sphincs_pub_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_sphincs_sig_size(sphincs_key* key) {
// #if defined(HAVE_PQC) && defined(HAVE_SPHINCS)
//     return wc_sphincs_sig_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
import "C"
import "unsafe"

// SphincsKey is a type alias for the wolfSSL sphincs_key struct (SPHINCS+ / SLH-DSA).
// sphincs_key structs are NOT thread-safe; callers must not share a key
// across goroutines without external synchronization.
type SphincsKey = C.struct_sphincs_key

// SPHINCS+ variant constants.
const (
	SPHINCS_FAST_VARIANT  = int(C.GO_SPHINCS_FAST_VARIANT)
	SPHINCS_SMALL_VARIANT = int(C.GO_SPHINCS_SMALL_VARIANT)
)

// Wc_SphincsInit initializes a sphincs_key struct.
// Returns 0 on success, negative on error.
func Wc_SphincsInit(key *C.struct_sphincs_key) int {
	return int(C.go_wc_sphincs_init(key))
}

// Wc_SphincsSetLevelAndOptim sets the security level and variant for key.
// level is 1, 3, or 5; optim is SPHINCS_FAST_VARIANT or SPHINCS_SMALL_VARIANT.
// Must be called before MakeKey or any import/export.
// Returns 0 on success, negative on error.
func Wc_SphincsSetLevelAndOptim(key *C.struct_sphincs_key, level byte, optim byte) int {
	return int(C.go_wc_sphincs_set_level_and_optim(key, C.byte(level), C.byte(optim)))
}

// Wc_SphincsGetLevelAndOptim retrieves the security level and variant for key.
// Returns 0 on success, negative on error.
func Wc_SphincsGetLevelAndOptim(key *C.struct_sphincs_key, level *byte, optim *byte) int {
	if level == nil || optim == nil {
		return BAD_FUNC_ARG
	}
	cLevel := C.byte(0)
	cOptim := C.byte(0)
	ret := int(C.go_wc_sphincs_get_level_and_optim(key, &cLevel, &cOptim))
	if ret == 0 {
		*level = byte(cLevel)
		*optim = byte(cOptim)
	}
	return ret
}

// Wc_SphincsFree releases resources associated with a sphincs_key struct.
func Wc_SphincsFree(key *C.struct_sphincs_key) {
	C.go_wc_sphincs_free(key)
}

// Wc_SphincsSignMsg signs msg with key, writing the signature into out.
// outLen is updated to the actual signature length on success.
// Returns 0 on success, negative on error.
func Wc_SphincsSignMsg(in []byte, inLen int, out []byte, outLen *int, key *C.struct_sphincs_key, rng *C.struct_WC_RNG) int {
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
	ret := int(C.go_wc_sphincs_sign_msg(
		inPtr, C.word32(inLen),
		(*C.byte)(unsafe.Pointer(&out[0])), &cOutLen,
		key, rng))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_SphincsVerifyMsg verifies sig against msg using key.
// res is set to 1 on valid signature, 0 on invalid.
// Returns 0 on success (check res for validity), negative on error.
func Wc_SphincsVerifyMsg(sig []byte, sigLen int, msg []byte, msgLen int, res *int, key *C.struct_sphincs_key) int {
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
	ret := int(C.go_wc_sphincs_verify_msg(
		(*C.byte)(unsafe.Pointer(&sig[0])), C.word32(sigLen),
		msgPtr, C.word32(msgLen),
		&cRes, key))
	if ret == 0 {
		*res = int(cRes)
	}
	return ret
}

// Wc_SphincsImportPublic imports a raw public key into key.
// inLen must be <= len(in).
// Returns 0 on success, negative on error.
func Wc_SphincsImportPublic(in []byte, inLen int, key *C.struct_sphincs_key) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_sphincs_import_public((*C.byte)(unsafe.Pointer(&in[0])), C.word32(inLen), key))
}

// Wc_SphincsImportPrivateOnly imports only the private key into key.
// privSz must be <= len(priv).
// Returns 0 on success, negative on error.
func Wc_SphincsImportPrivateOnly(priv []byte, privSz int, key *C.struct_sphincs_key) int {
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if len(priv) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_sphincs_import_private_only((*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz), key))
}

// Wc_SphincsImportPrivateKey imports both the private and public key into key.
// privSz must be <= len(priv); pubSz must be <= len(pub).
// Returns 0 on success, negative on error.
func Wc_SphincsImportPrivateKey(priv []byte, privSz int, pub []byte, pubSz int, key *C.struct_sphincs_key) int {
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if pubSz < 0 || pubSz > len(pub) {
		return BAD_FUNC_ARG
	}
	if len(priv) == 0 || len(pub) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_sphincs_import_private_key(
		(*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz),
		(*C.byte)(unsafe.Pointer(&pub[0])), C.word32(pubSz),
		key))
}

// Wc_SphincsExportPublic exports the public key from key into out.
// outLen is updated to the actual number of bytes written on success.
// Returns 0 on success, negative on error.
func Wc_SphincsExportPublic(key *C.struct_sphincs_key, out []byte, outLen *int) int {
	if outLen == nil || len(out) == 0 {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_sphincs_export_public(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_SphincsExportPrivateOnly exports only the private key from key into out.
// outLen is updated to the actual number of bytes written on success.
// Returns 0 on success, negative on error.
func Wc_SphincsExportPrivateOnly(key *C.struct_sphincs_key, out []byte, outLen *int) int {
	if outLen == nil || len(out) == 0 {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_sphincs_export_private_only(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_SphincsExportKey exports both the private and public key from key.
// privSz and pubSz are updated to the actual byte counts on success.
// Returns 0 on success, negative on error.
func Wc_SphincsExportKey(key *C.struct_sphincs_key, priv []byte, privSz *int, pub []byte, pubSz *int) int {
	if privSz == nil || len(priv) == 0 {
		return BAD_FUNC_ARG
	}
	if pubSz == nil || len(pub) == 0 {
		return BAD_FUNC_ARG
	}
	cPrivSz := C.word32(len(priv))
	cPubSz := C.word32(len(pub))
	ret := int(C.go_wc_sphincs_export_key(key,
		(*C.byte)(unsafe.Pointer(&priv[0])), &cPrivSz,
		(*C.byte)(unsafe.Pointer(&pub[0])), &cPubSz))
	if ret == 0 {
		*privSz = int(cPrivSz)
		*pubSz = int(cPubSz)
	}
	return ret
}

// Wc_SphincsSize returns the private key size for key's configured level/variant.
// Returns the size in bytes, or negative on error.
func Wc_SphincsSize(key *C.struct_sphincs_key) int {
	return int(C.go_wc_sphincs_size(key))
}

// Wc_SphincsPrivSize returns the full private key size for key's configured level/variant.
// Returns the size in bytes, or negative on error.
func Wc_SphincsPrivSize(key *C.struct_sphincs_key) int {
	return int(C.go_wc_sphincs_priv_size(key))
}

// Wc_SphincsPubSize returns the public key size for key's configured level/variant.
// Returns the size in bytes, or negative on error.
func Wc_SphincsPubSize(key *C.struct_sphincs_key) int {
	return int(C.go_wc_sphincs_pub_size(key))
}

// Wc_SphincsSigSize returns the signature size for key's configured level/variant.
// Returns the size in bytes, or negative on error.
func Wc_SphincsSigSize(key *C.struct_sphincs_key) int {
	return int(C.go_wc_sphincs_sig_size(key))
}
