/* pwdbased.go
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

// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/pwdbased.h>
// #ifndef NO_PWDBASED
// /* PKCS12_PBKDF stubs not needed — present whenever NO_PWDBASED is not defined */
// #else
// static int wc_PKCS12_PBKDF(byte* output, const byte* passwd, int passLen,
//                             const byte* salt, int saltLen, int iterations,
//                             int kLen, int hashType, int id) {
//     (void)output; (void)passwd; (void)passLen; (void)salt; (void)saltLen;
//     (void)iterations; (void)kLen; (void)hashType; (void)id;
//     return -174;
// }
// static int wc_PKCS12_PBKDF_ex(byte* output, const byte* passwd, int passLen,
//                                const byte* salt, int saltLen, int iterations,
//                                int kLen, int hashType, int id, void* heap) {
//     (void)output; (void)passwd; (void)passLen; (void)salt; (void)saltLen;
//     (void)iterations; (void)kLen; (void)hashType; (void)id; (void)heap;
//     return -174;
// }
// #endif
// #ifdef HAVE_SCRYPT
// /* scrypt functions are declared in pwdbased.h when HAVE_SCRYPT is set */
// #else
// static int wc_scrypt(byte* output, const byte* passwd, int passLen,
//                      const byte* salt, int saltLen, int cost,
//                      int blockSize, int parallel, int dkLen) {
//     (void)output; (void)passwd; (void)passLen; (void)salt; (void)saltLen;
//     (void)cost; (void)blockSize; (void)parallel; (void)dkLen;
//     return -174;
// }
// static int wc_scrypt_ex(byte* output, const byte* passwd, int passLen,
//                         const byte* salt, int saltLen, word32 iterations,
//                         int blockSize, int parallel, int dkLen) {
//     (void)output; (void)passwd; (void)passLen; (void)salt; (void)saltLen;
//     (void)iterations; (void)blockSize; (void)parallel; (void)dkLen;
//     return -174;
// }
// #endif
import "C"
import "unsafe"

// Wc_PKCS12_PBKDF derives a key using the PKCS#12 password-based KDF.
// passwd and salt may be nil/empty (passLen or saltLen must be 0 in that case).
// id selects the derived material: 1=key, 2=IV, 3=MAC key.
// Returns 0 on success, negative wolfcrypt error code on failure.
func Wc_PKCS12_PBKDF(out []byte, passwd []byte, passLen int, salt []byte, saltLen int,
	iterations int, kLen int, hashType int, id int) int {
	if passLen < 0 || passLen > len(passwd) {
		return BAD_FUNC_ARG
	}
	if saltLen < 0 || saltLen > len(salt) {
		return BAD_FUNC_ARG
	}
	if kLen < 0 || kLen > len(out) {
		return BAD_FUNC_ARG
	}
	if iterations <= 0 {
		return BAD_FUNC_ARG
	}
	var outPtr *C.uchar
	if len(out) > 0 {
		outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
	}
	var passwdPtr *C.uchar
	if len(passwd) > 0 {
		passwdPtr = (*C.uchar)(unsafe.Pointer(&passwd[0]))
	}
	var saltPtr *C.uchar
	if len(salt) > 0 {
		saltPtr = (*C.uchar)(unsafe.Pointer(&salt[0]))
	}
	return int(C.wc_PKCS12_PBKDF(outPtr, passwdPtr, C.int(passLen),
		saltPtr, C.int(saltLen), C.int(iterations),
		C.int(kLen), C.int(hashType), C.int(id)))
}

// Wc_PKCS12_PBKDF_ex is the extended form of Wc_PKCS12_PBKDF; heap is passed
// as NULL (standard system allocator).
// Returns 0 on success, negative wolfcrypt error code on failure.
func Wc_PKCS12_PBKDF_ex(out []byte, passwd []byte, passLen int, salt []byte, saltLen int,
	iterations int, kLen int, hashType int, id int) int {
	if passLen < 0 || passLen > len(passwd) {
		return BAD_FUNC_ARG
	}
	if saltLen < 0 || saltLen > len(salt) {
		return BAD_FUNC_ARG
	}
	if kLen < 0 || kLen > len(out) {
		return BAD_FUNC_ARG
	}
	if iterations <= 0 {
		return BAD_FUNC_ARG
	}
	var outPtr *C.uchar
	if len(out) > 0 {
		outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
	}
	var passwdPtr *C.uchar
	if len(passwd) > 0 {
		passwdPtr = (*C.uchar)(unsafe.Pointer(&passwd[0]))
	}
	var saltPtr *C.uchar
	if len(salt) > 0 {
		saltPtr = (*C.uchar)(unsafe.Pointer(&salt[0]))
	}
	return int(C.wc_PKCS12_PBKDF_ex(outPtr, passwdPtr, C.int(passLen),
		saltPtr, C.int(saltLen), C.int(iterations),
		C.int(kLen), C.int(hashType), C.int(id), unsafe.Pointer(nil)))
}

// Wc_Scrypt derives a key using the scrypt KDF (RFC 7914).
// cost is the CPU/memory cost parameter N (must be a power of two).
// blockSize is r, parallel is p.
// Returns 0 on success, negative wolfcrypt error code on failure.
// Returns -174 (NOT_COMPILED_IN) if wolfSSL was built without HAVE_SCRYPT.
func Wc_Scrypt(out []byte, passwd []byte, passLen int, salt []byte, saltLen int,
	cost int, blockSize int, parallel int, dkLen int) int {
	if passLen < 0 || passLen > len(passwd) {
		return BAD_FUNC_ARG
	}
	if saltLen < 0 || saltLen > len(salt) {
		return BAD_FUNC_ARG
	}
	if dkLen < 0 || dkLen > len(out) {
		return BAD_FUNC_ARG
	}
	if cost <= 0 {
		return BAD_FUNC_ARG
	}
	var outPtr *C.uchar
	if len(out) > 0 {
		outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
	}
	var passwdPtr *C.uchar
	if len(passwd) > 0 {
		passwdPtr = (*C.uchar)(unsafe.Pointer(&passwd[0]))
	}
	var saltPtr *C.uchar
	if len(salt) > 0 {
		saltPtr = (*C.uchar)(unsafe.Pointer(&salt[0]))
	}
	return int(C.wc_scrypt(outPtr, passwdPtr, C.int(passLen),
		saltPtr, C.int(saltLen), C.int(cost),
		C.int(blockSize), C.int(parallel), C.int(dkLen)))
}

// Wc_Scrypt_ex derives a key using the scrypt KDF with an explicit iterations
// parameter (wc_scrypt_ex variant).  iterations corresponds to the N parameter
// expressed as the exponent for 2^N in some wolfSSL builds; see wolfSSL docs.
// Returns 0 on success, negative wolfcrypt error code on failure.
// Returns -174 (NOT_COMPILED_IN) if wolfSSL was built without HAVE_SCRYPT.
func Wc_Scrypt_ex(out []byte, passwd []byte, passLen int, salt []byte, saltLen int,
	iterations int, blockSize int, parallel int, dkLen int) int {
	if passLen < 0 || passLen > len(passwd) {
		return BAD_FUNC_ARG
	}
	if saltLen < 0 || saltLen > len(salt) {
		return BAD_FUNC_ARG
	}
	if dkLen < 0 || dkLen > len(out) {
		return BAD_FUNC_ARG
	}
	if iterations <= 0 {
		return BAD_FUNC_ARG
	}
	var outPtr *C.uchar
	if len(out) > 0 {
		outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
	}
	var passwdPtr *C.uchar
	if len(passwd) > 0 {
		passwdPtr = (*C.uchar)(unsafe.Pointer(&passwd[0]))
	}
	var saltPtr *C.uchar
	if len(salt) > 0 {
		saltPtr = (*C.uchar)(unsafe.Pointer(&salt[0]))
	}
	return int(C.wc_scrypt_ex(outPtr, passwdPtr, C.int(passLen),
		saltPtr, C.int(saltLen), C.word32(iterations),
		C.int(blockSize), C.int(parallel), C.int(dkLen)))
}
