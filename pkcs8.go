/* pkcs8.go
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
// PKCS#8 private key wrapping, unwrapping, encryption, and decryption.
// All functions in this file require wolfSSL built with HAVE_PKCS8.

package wolfSSL

// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/asn_public.h>
// #include <wolfssl/wolfcrypt/random.h>
//
// /* ---- wc_GetPkcs8TraditionalOffset --------------------------------------- */
//
// static int go_wc_GetPkcs8TraditionalOffset(byte* input, word32* inOutIdx,
//         word32 sz) {
// #ifdef HAVE_PKCS8
//     return wc_GetPkcs8TraditionalOffset(input, inOutIdx, sz);
// #else
//     (void)input; (void)inOutIdx; (void)sz;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wc_CreatePKCS8Key -------------------------------------------------- */
//
// static int go_wc_CreatePKCS8Key(byte* out, word32* outSz,
//         byte* key, word32 keySz, int algoID,
//         const byte* curveOID, word32 oidSz) {
// #ifdef HAVE_PKCS8
//     return wc_CreatePKCS8Key(out, outSz, key, keySz, algoID, curveOID, oidSz);
// #else
//     (void)out; (void)outSz; (void)key; (void)keySz;
//     (void)algoID; (void)curveOID; (void)oidSz;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wc_EncryptPKCS8Key ------------------------------------------------- */
//
// static int go_wc_EncryptPKCS8Key(byte* key, word32 keySz,
//         byte* out, word32* outSz,
//         const char* password, int passwordSz,
//         int vPKCS, int pbeOid, int encAlgId,
//         byte* salt, word32 saltSz, int itt,
//         WC_RNG* rng, void* heap) {
// #ifdef HAVE_PKCS8
//     return wc_EncryptPKCS8Key(key, keySz, out, outSz, password, passwordSz,
//                               vPKCS, pbeOid, encAlgId, salt, saltSz, itt,
//                               rng, heap);
// #else
//     (void)key; (void)keySz; (void)out; (void)outSz;
//     (void)password; (void)passwordSz; (void)vPKCS; (void)pbeOid;
//     (void)encAlgId; (void)salt; (void)saltSz; (void)itt;
//     (void)rng; (void)heap;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wc_DecryptPKCS8Key ------------------------------------------------- */
//
// static int go_wc_DecryptPKCS8Key(byte* input, word32 sz,
//         const char* password, int passwordSz) {
// #ifdef HAVE_PKCS8
//     return wc_DecryptPKCS8Key(input, sz, password, passwordSz);
// #else
//     (void)input; (void)sz; (void)password; (void)passwordSz;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wc_CreateEncryptedPKCS8Key ----------------------------------------- */
//
// static int go_wc_CreateEncryptedPKCS8Key(byte* key, word32 keySz,
//         byte* out, word32* outSz,
//         const char* password, int passwordSz,
//         int vPKCS, int pbeOid, int encAlgId,
//         byte* salt, word32 saltSz, int itt,
//         WC_RNG* rng, void* heap) {
// #ifdef HAVE_PKCS8
//     return wc_CreateEncryptedPKCS8Key(key, keySz, out, outSz, password,
//                                       passwordSz, vPKCS, pbeOid, encAlgId,
//                                       salt, saltSz, itt, rng, heap);
// #else
//     (void)key; (void)keySz; (void)out; (void)outSz;
//     (void)password; (void)passwordSz; (void)vPKCS; (void)pbeOid;
//     (void)encAlgId; (void)salt; (void)saltSz; (void)itt;
//     (void)rng; (void)heap;
//     return NOT_COMPILED_IN;
// #endif
// }
import "C"
import (
	"unsafe"
)

// ENC_PKCS8_VER_PKCS12 and ENC_PKCS8_VER_PKCS5 select the PKCS version for
// password-based encryption. Pass one of these as vPKCS to
// Wc_EncryptPKCS8Key and Wc_CreateEncryptedPKCS8Key.
const ENC_PKCS8_VER_PKCS12 = int(C.ENC_PKCS8_VER_PKCS12)
const ENC_PKCS8_VER_PKCS5 = int(C.ENC_PKCS8_VER_PKCS5)

// PBE OID constants for the pbeOid parameter of Wc_EncryptPKCS8Key and
// Wc_CreateEncryptedPKCS8Key.
const ENC_PKCS8_PBES2 = int(C.ENC_PKCS8_PBES2)
const ENC_PKCS8_PBE_SHA1_RC4_128 = int(C.ENC_PKCS8_PBE_SHA1_RC4_128)
const ENC_PKCS8_PBE_SHA1_DES = int(C.ENC_PKCS8_PBE_SHA1_DES)
const ENC_PKCS8_PBE_SHA1_DES3 = int(C.ENC_PKCS8_PBE_SHA1_DES3)
const ENC_PKCS8_PBE_SHA1_40RC2_CBC = int(C.ENC_PKCS8_PBE_SHA1_40RC2_CBC)
const ENC_PKCS8_PBES1_MD5_DES = int(C.ENC_PKCS8_PBES1_MD5_DES)
const ENC_PKCS8_PBES1_SHA1_DES = int(C.ENC_PKCS8_PBES1_SHA1_DES)

// Encryption algorithm constants for the encAlgId parameter used with
// PBES2 (ENC_PKCS8_PBES2).
const ENC_PKCS8_ALG_AES128CBC = int(C.ENC_PKCS8_ALG_AES128CBC)
const ENC_PKCS8_ALG_AES256CBC = int(C.ENC_PKCS8_ALG_AES256CBC)
const ENC_PKCS8_ALG_DES = int(C.ENC_PKCS8_ALG_DES)
const ENC_PKCS8_ALG_DES3 = int(C.ENC_PKCS8_ALG_DES3)

// Wc_GetPkcs8TraditionalOffset locates the traditional (non-PKCS#8) private
// key inside a DER-encoded PKCS#8 blob. inOutIdx is both an input (byte
// offset to start parsing) and output (updated to the start of the embedded
// traditional key). sz is the number of valid bytes in input.
//
// Returns the length of the embedded traditional key on success (>= 0),
// or a negative error code on failure.
// Requires wolfSSL built with HAVE_PKCS8.
func Wc_GetPkcs8TraditionalOffset(input []byte, inOutIdx *int, sz int) int {
	if inOutIdx == nil {
		return BAD_FUNC_ARG
	}
	if sz < 0 || sz > len(input) {
		return BAD_FUNC_ARG
	}
	if len(input) == 0 {
		return BAD_FUNC_ARG
	}
	idx := C.word32(*inOutIdx)
	ret := int(C.go_wc_GetPkcs8TraditionalOffset(
		(*C.uchar)(unsafe.Pointer(&input[0])), &idx, C.word32(sz)))
	if ret >= 0 {
		*inOutIdx = int(idx)
	}
	return ret
}

// Wc_CreatePKCS8Key wraps a DER-encoded traditional private key in a PKCS#8
// PrivateKeyInfo envelope and writes the result to out.
//
// algoID is the key algorithm OID (e.g. ECDSAk, RSAk). curveOID and oidSz
// specify the optional curve OID for ECC keys; pass nil and 0 for RSA.
//
// When out is nil the function performs a size probe: it sets *outSz to the
// required buffer size and returns LENGTH_ONLY_E (a negative value). Callers
// should allocate a buffer of that size and call again with out != nil.
//
// When out is not nil, returns the number of bytes written to out on success
// (> 0), or a negative error code on failure.
// Requires wolfSSL built with HAVE_PKCS8.
func Wc_CreatePKCS8Key(out []byte, outSz *int, key []byte, keySz int, algoID int, curveOID []byte, oidSz int) int {
	if outSz == nil {
		return BAD_FUNC_ARG
	}
	if keySz < 0 || keySz > len(key) {
		return BAD_FUNC_ARG
	}
	if oidSz < 0 || oidSz > len(curveOID) {
		return BAD_FUNC_ARG
	}
	if len(key) == 0 {
		return BAD_FUNC_ARG
	}

	cOutSz := C.word32(*outSz)

	var outPtr *C.uchar
	if len(out) > 0 {
		outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
	}

	var curvePtr *C.uchar
	if oidSz > 0 {
		curvePtr = (*C.uchar)(unsafe.Pointer(&curveOID[0]))
	}

	ret := int(C.go_wc_CreatePKCS8Key(
		outPtr, &cOutSz,
		(*C.uchar)(unsafe.Pointer(&key[0])), C.word32(keySz),
		C.int(algoID),
		curvePtr, C.word32(oidSz)))
	*outSz = int(cOutSz)
	return ret
}

// Wc_EncryptPKCS8Key encrypts an already-wrapped PKCS#8 key blob using
// password-based encryption and writes the result to out.
//
// key/keySz: PKCS#8 DER blob to encrypt.
// out/outSz: output buffer; outSz is in/out (capacity on entry, bytes written
//
//	on exit). When out is nil the function sets *outSz to the required size
//	and returns LENGTH_ONLY_E (negative).
//
// password/passwordSz: encryption passphrase.
// vPKCS: version — ENC_PKCS8_VER_PKCS12 or ENC_PKCS8_VER_PKCS5.
// pbeOid: PBE OID constant (ENC_PKCS8_PBES2, ENC_PKCS8_PBE_SHA1_DES3, …).
// encAlgId: encryption algorithm ID, used only with PBES2.
// salt/saltSz: optional salt; pass nil/0 to have wolfSSL generate one.
// itt: PBKDF2 iteration count.
// rng: initialized WC_RNG (required when salt is nil).
//
// Returns the number of bytes written to out on success (> 0), or a negative
// error code on failure.
// Requires wolfSSL built with HAVE_PKCS8.
func Wc_EncryptPKCS8Key(key []byte, keySz int, out []byte, outSz *int, password string, passwordSz int, vPKCS int, pbeOid int, encAlgId int, salt []byte, saltSz int, itt int, rng *C.struct_WC_RNG, heap unsafe.Pointer) int {
	if outSz == nil {
		return BAD_FUNC_ARG
	}
	if keySz < 0 || keySz > len(key) {
		return BAD_FUNC_ARG
	}
	if passwordSz < 0 || passwordSz > len(password) {
		return BAD_FUNC_ARG
	}
	if saltSz < 0 || saltSz > len(salt) {
		return BAD_FUNC_ARG
	}
	if len(key) == 0 {
		return BAD_FUNC_ARG
	}

	cOutSz := C.word32(*outSz)

	var outPtr *C.uchar
	if len(out) > 0 {
		outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
	}

	var saltPtr *C.uchar
	if saltSz > 0 {
		saltPtr = (*C.uchar)(unsafe.Pointer(&salt[0]))
	}

	cPass := C.CString(password)
	defer C.free(unsafe.Pointer(cPass))

	ret := int(C.go_wc_EncryptPKCS8Key(
		(*C.uchar)(unsafe.Pointer(&key[0])), C.word32(keySz),
		outPtr, &cOutSz,
		cPass, C.int(passwordSz),
		C.int(vPKCS), C.int(pbeOid), C.int(encAlgId),
		saltPtr, C.word32(saltSz), C.int(itt),
		rng, heap))
	*outSz = int(cOutSz)
	return ret
}

// Wc_DecryptPKCS8Key decrypts a DER-encoded EncryptedPrivateKeyInfo blob
// in place. The decrypted PKCS#8 content overwrites the beginning of input.
//
// input is modified in place by wolfSSL; it must be a writable slice of at
// least sz bytes.
// sz is the number of valid bytes of encrypted data in input.
// password/passwordSz: decryption passphrase.
//
// Returns the number of bytes of decrypted PKCS#8 data in input on success
// (> 0), or a negative error code on failure.
// Requires wolfSSL built with HAVE_PKCS8.
func Wc_DecryptPKCS8Key(input []byte, sz int, password string, passwordSz int) int {
	if sz < 0 || sz > len(input) {
		return BAD_FUNC_ARG
	}
	if passwordSz < 0 || passwordSz > len(password) {
		return BAD_FUNC_ARG
	}
	if len(input) == 0 {
		return BAD_FUNC_ARG
	}

	cPass := C.CString(password)
	defer C.free(unsafe.Pointer(cPass))

	return int(C.go_wc_DecryptPKCS8Key(
		(*C.uchar)(unsafe.Pointer(&input[0])), C.word32(sz),
		cPass, C.int(passwordSz)))
}

// Wc_CreateEncryptedPKCS8Key combines PKCS#8 wrapping and password-based
// encryption in a single call. It takes a traditional DER-encoded private key,
// wraps it in a PKCS#8 envelope, encrypts it, and writes the result to out.
//
// key/keySz: traditional (non-PKCS#8) DER private key.
// out/outSz: output buffer; outSz is in/out (capacity on entry, bytes written
//
//	on exit). When out is nil the function sets *outSz to the required size
//	and returns LENGTH_ONLY_E (negative).
//
// password/passwordSz: encryption passphrase.
// vPKCS: version — ENC_PKCS8_VER_PKCS12 or ENC_PKCS8_VER_PKCS5.
// pbeOid: PBE OID constant (ENC_PKCS8_PBES2, ENC_PKCS8_PBE_SHA1_DES3, …).
// encAlgId: encryption algorithm ID, used only with PBES2.
// salt/saltSz: optional salt; pass nil/0 to have wolfSSL generate one.
// itt: PBKDF2 iteration count.
// rng: initialized WC_RNG (required when salt is nil).
//
// Returns the number of bytes written to out on success (> 0), or a negative
// error code on failure.
// Requires wolfSSL built with HAVE_PKCS8.
func Wc_CreateEncryptedPKCS8Key(key []byte, keySz int, out []byte, outSz *int, password string, passwordSz int, vPKCS int, pbeOid int, encAlgId int, salt []byte, saltSz int, itt int, rng *C.struct_WC_RNG, heap unsafe.Pointer) int {
	if outSz == nil {
		return BAD_FUNC_ARG
	}
	if keySz < 0 || keySz > len(key) {
		return BAD_FUNC_ARG
	}
	if passwordSz < 0 || passwordSz > len(password) {
		return BAD_FUNC_ARG
	}
	if saltSz < 0 || saltSz > len(salt) {
		return BAD_FUNC_ARG
	}
	if len(key) == 0 {
		return BAD_FUNC_ARG
	}

	cOutSz := C.word32(*outSz)

	var outPtr *C.uchar
	if len(out) > 0 {
		outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
	}

	var saltPtr *C.uchar
	if saltSz > 0 {
		saltPtr = (*C.uchar)(unsafe.Pointer(&salt[0]))
	}

	cPass := C.CString(password)
	defer C.free(unsafe.Pointer(cPass))

	ret := int(C.go_wc_CreateEncryptedPKCS8Key(
		(*C.uchar)(unsafe.Pointer(&key[0])), C.word32(keySz),
		outPtr, &cOutSz,
		cPass, C.int(passwordSz),
		C.int(vPKCS), C.int(pbeOid), C.int(encAlgId),
		saltPtr, C.word32(saltSz), C.int(itt),
		rng, heap))
	*outSz = int(cOutSz)
	return ret
}
