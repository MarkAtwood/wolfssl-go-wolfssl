/* curve448.go
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

// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/curve448.h>
// #include <wolfssl/wolfcrypt/random.h>
//
// #ifndef HAVE_CURVE448
// typedef struct curve448_key {} curve448_key;
// #define EC448_LITTLE_ENDIAN 0
// #define EC448_BIG_ENDIAN    1
// #endif
//
// /* --- Init / Free --- */
//
// static int go_wc_curve448_init(curve448_key* key) {
// #ifdef HAVE_CURVE448
//     return wc_curve448_init(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static void go_wc_curve448_free(curve448_key* key) {
// #ifdef HAVE_CURVE448
//     wc_curve448_free(key);
// #endif
// }
//
// /* --- Key generation --- */
//
// static int go_wc_curve448_make_key(WC_RNG* rng, int keysize, curve448_key* key) {
// #ifdef HAVE_CURVE448
//     return wc_curve448_make_key(rng, keysize, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Shared secret --- */
//
// static int go_wc_curve448_shared_secret(curve448_key* private_key,
//                                         curve448_key* public_key,
//                                         byte* out, word32* outlen) {
// #ifdef HAVE_CURVE448
//     return wc_curve448_shared_secret(private_key, public_key, out, outlen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_curve448_shared_secret_ex(curve448_key* private_key,
//                                            curve448_key* public_key,
//                                            byte* out, word32* outlen, int endian) {
// #ifdef HAVE_CURVE448
//     return wc_curve448_shared_secret_ex(private_key, public_key, out, outlen, endian);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Key import --- */
//
// static int go_wc_curve448_import_private(const byte* priv, word32 privSz,
//                                          curve448_key* key) {
// #ifdef HAVE_CURVE448
//     return wc_curve448_import_private(priv, privSz, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_curve448_import_private_raw(const byte* priv, word32 privSz,
//                                              const byte* pub, word32 pubSz,
//                                              curve448_key* key) {
// #ifdef HAVE_CURVE448
//     return wc_curve448_import_private_raw(priv, privSz, pub, pubSz, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_curve448_import_private_raw_ex(const byte* priv, word32 privSz,
//                                                 const byte* pub, word32 pubSz,
//                                                 curve448_key* key, int endian) {
// #ifdef HAVE_CURVE448
//     return wc_curve448_import_private_raw_ex(priv, privSz, pub, pubSz, key, endian);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_curve448_import_public(const byte* in, word32 inLen,
//                                         curve448_key* key) {
// #ifdef HAVE_CURVE448
//     return wc_curve448_import_public(in, inLen, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_curve448_import_public_raw(const byte* in, word32 inLen,
//                                             curve448_key* key) {
// #ifdef HAVE_CURVE448
//     return wc_curve448_import_public_ex(in, inLen, key, EC448_LITTLE_ENDIAN);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Key export --- */
//
// static int go_wc_curve448_export_private_raw(curve448_key* key, byte* out,
//                                              word32* outLen) {
// #ifdef HAVE_CURVE448
//     return wc_curve448_export_private_raw(key, out, outLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_curve448_export_private_raw_le(curve448_key* key, byte* out,
//                                                 word32* outLen) {
// #ifdef HAVE_CURVE448
//     return wc_curve448_export_private_raw_ex(key, out, outLen, EC448_LITTLE_ENDIAN);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_curve448_export_public(curve448_key* key, byte* out,
//                                         word32* outLen) {
// #ifdef HAVE_CURVE448
//     return wc_curve448_export_public(key, out, outLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_curve448_export_public_raw(curve448_key* key, byte* out,
//                                             word32* outLen) {
// #ifdef HAVE_CURVE448
//     return wc_curve448_export_public_ex(key, out, outLen, EC448_LITTLE_ENDIAN);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Size query --- */
//
// static int go_wc_curve448_size(curve448_key* key) {
// #ifdef HAVE_CURVE448
//     return wc_curve448_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
import "C"
import "unsafe"

// Curve448Key is a type alias for the wolfSSL curve448_key struct.
// curve448_key structs are NOT thread-safe; callers must not share a key
// across goroutines without external synchronization.
type Curve448Key = C.struct_curve448_key

// Curve448 key size constants.
const (
	CURVE448_KEY_SIZE     = int(C.CURVE448_KEY_SIZE)
	CURVE448_PUB_KEY_SIZE = int(C.CURVE448_PUB_KEY_SIZE)
)

// Wc_Curve448Init initializes a curve448_key struct.
// Returns 0 on success, negative on error.
func Wc_Curve448Init(key *C.struct_curve448_key) int {
	return int(C.go_wc_curve448_init(key))
}

// Wc_Curve448Free releases resources associated with a curve448_key struct.
func Wc_Curve448Free(key *C.struct_curve448_key) {
	C.go_wc_curve448_free(key)
}

// Wc_Curve448MakeKey generates a new Curve448 key pair into key.
// keysize must be CURVE448_KEY_SIZE (56).
// Returns 0 on success, negative on error.
func Wc_Curve448MakeKey(rng *C.struct_WC_RNG, keysize int, key *C.struct_curve448_key) int {
	return int(C.go_wc_curve448_make_key(rng, C.int(keysize), key))
}

// Wc_Curve448SharedSecret computes the shared secret from private_key and public_key,
// writing the result into out. outLen is updated to the actual byte count on success.
// out must be at least CURVE448_KEY_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Curve448SharedSecret(privateKey, publicKey *C.struct_curve448_key, out []byte, outLen *int) int {
	if outLen == nil || len(out) < CURVE448_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_curve448_shared_secret(
		privateKey, publicKey,
		(*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_Curve448SharedSecretEx computes the shared secret with an explicit endianness flag.
// endian is EC448_LITTLE_ENDIAN (0) or EC448_BIG_ENDIAN (1).
// out must be at least CURVE448_KEY_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Curve448SharedSecretEx(privateKey, publicKey *C.struct_curve448_key, out []byte, outLen *int, endian int) int {
	if outLen == nil || len(out) < CURVE448_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_curve448_shared_secret_ex(
		privateKey, publicKey,
		(*C.byte)(unsafe.Pointer(&out[0])), &cOutLen, C.int(endian)))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_Curve448ImportPrivate imports a private key from priv (big-endian by default).
// privSz must be <= len(priv).
// Returns 0 on success, negative on error.
func Wc_Curve448ImportPrivate(priv []byte, privSz int, key *C.struct_curve448_key) int {
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if len(priv) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_curve448_import_private(
		(*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz), key))
}

// Wc_Curve448ImportPrivateRaw imports a private key and public key together.
// privSz must be <= len(priv); pubSz must be <= len(pub).
// Returns 0 on success, negative on error.
func Wc_Curve448ImportPrivateRaw(priv []byte, privSz int, pub []byte, pubSz int, key *C.struct_curve448_key) int {
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if pubSz < 0 || pubSz > len(pub) {
		return BAD_FUNC_ARG
	}
	if len(priv) == 0 || len(pub) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_curve448_import_private_raw(
		(*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz),
		(*C.byte)(unsafe.Pointer(&pub[0])), C.word32(pubSz),
		key))
}

// Wc_Curve448ImportPrivateRawEx imports a private key and public key together,
// with an explicit endianness flag.
// endian is EC448_LITTLE_ENDIAN (0) or EC448_BIG_ENDIAN (1).
// Returns 0 on success, negative on error.
func Wc_Curve448ImportPrivateRawEx(priv []byte, privSz int, pub []byte, pubSz int, key *C.struct_curve448_key, endian int) int {
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if pubSz < 0 || pubSz > len(pub) {
		return BAD_FUNC_ARG
	}
	if len(priv) == 0 || len(pub) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_curve448_import_private_raw_ex(
		(*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz),
		(*C.byte)(unsafe.Pointer(&pub[0])), C.word32(pubSz),
		key, C.int(endian)))
}

// Wc_Curve448ImportPublic imports a public key from in.
// inLen must be <= len(in).
// Returns 0 on success, negative on error.
func Wc_Curve448ImportPublic(in []byte, inLen int, key *C.struct_curve448_key) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_curve448_import_public(
		(*C.byte)(unsafe.Pointer(&in[0])), C.word32(inLen), key))
}

// Wc_Curve448ImportPublicRaw imports a raw public key from in.
// inLen must be <= len(in).
// Returns 0 on success, negative on error.
func Wc_Curve448ImportPublicRaw(in []byte, inLen int, key *C.struct_curve448_key) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_curve448_import_public_raw(
		(*C.byte)(unsafe.Pointer(&in[0])), C.word32(inLen), key))
}

// Wc_Curve448ExportPrivate exports the raw private key from key into out in
// big-endian byte order (wolfSSL default).
// outLen is updated to the actual number of bytes written on success.
// out must be at least CURVE448_KEY_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Curve448ExportPrivate(key *C.struct_curve448_key, out []byte, outLen *int) int {
	if outLen == nil || len(out) < CURVE448_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_curve448_export_private_raw(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_Curve448ExportPrivateRaw exports the raw private key from key into out in
// little-endian byte order (matching all other *Raw export functions).
// outLen is updated to the actual number of bytes written on success.
// out must be at least CURVE448_KEY_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Curve448ExportPrivateRaw(key *C.struct_curve448_key, out []byte, outLen *int) int {
	if outLen == nil || len(out) < CURVE448_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_curve448_export_private_raw_le(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_Curve448ExportPublic exports the public key from key into out.
// outLen is updated to the actual number of bytes written on success.
// out must be at least CURVE448_PUB_KEY_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Curve448ExportPublic(key *C.struct_curve448_key, out []byte, outLen *int) int {
	if outLen == nil || len(out) < CURVE448_PUB_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_curve448_export_public(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_Curve448ExportPublicRaw exports the raw public key from key into out.
// outLen is updated to the actual number of bytes written on success.
// out must be at least CURVE448_PUB_KEY_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Curve448ExportPublicRaw(key *C.struct_curve448_key, out []byte, outLen *int) int {
	if outLen == nil || len(out) < CURVE448_PUB_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_curve448_export_public_raw(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_Curve448Size returns the key size for key (CURVE448_KEY_SIZE = 56).
// Returns the size in bytes, or negative on error.
func Wc_Curve448Size(key *C.struct_curve448_key) int {
	return int(C.go_wc_curve448_size(key))
}
