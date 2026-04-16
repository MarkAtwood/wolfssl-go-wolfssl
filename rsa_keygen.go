/* rsa_keygen.go
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
// #include <wolfssl/wolfcrypt/rsa.h>
// #include <wolfssl/wolfcrypt/random.h>
//
// /* ---- Key generation --------------------------------------------------- */
//
// static int go_wc_MakeRsaKey(RsaKey* key, int size, long e, WC_RNG* rng) {
// #if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
//     return wc_MakeRsaKey(key, size, e, rng);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- Key export ------------------------------------------------------- */
//
// static int go_wc_RsaExportKey(const RsaKey* key,
//         byte* e,  word32* eSz,
//         byte* n,  word32* nSz,
//         byte* d,  word32* dSz,
//         byte* p,  word32* pSz,
//         byte* q,  word32* qSz) {
// #ifndef NO_RSA
//     return wc_RsaExportKey(key, e, eSz, n, nSz, d, dSz, p, pSz, q, qSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
import "C"
import "unsafe"

// Wc_MakeRsaKey generates an RSA key pair of the given bit size using the
// supplied RNG. e is the public exponent (typically 65537).
// Requires wolfSSL built with WOLFSSL_KEY_GEN.
// Returns 0 on success, negative on error.
func Wc_MakeRsaKey(key *C.struct_RsaKey, size int, e int, rng *C.struct_WC_RNG) int {
	return int(C.go_wc_MakeRsaKey(key, C.int(size), C.long(e), rng))
}

// Wc_RsaExportKey exports the raw components of an RSA key into caller-supplied
// buffers. The *Sz parameters are in/out: on input they hold the buffer
// capacities; on a successful return they hold the actual byte lengths written.
// d, p, and q are the private components and will be zero-length for a
// public-only key. The function uses the wolfSSL parameter order: e, n, d, p, q.
// Returns 0 on success, negative on error.
func Wc_RsaExportKey(key *C.struct_RsaKey,
	e []byte, eSz *int,
	n []byte, nSz *int,
	d []byte, dSz *int,
	p []byte, pSz *int,
	q []byte, qSz *int) int {

	if eSz == nil || nSz == nil || dSz == nil || pSz == nil || qSz == nil {
		return BAD_FUNC_ARG
	}
	if *eSz < 0 || *eSz > len(e) {
		return BAD_FUNC_ARG
	}
	if *nSz < 0 || *nSz > len(n) {
		return BAD_FUNC_ARG
	}
	if *dSz < 0 || *dSz > len(d) {
		return BAD_FUNC_ARG
	}
	if *pSz < 0 || *pSz > len(p) {
		return BAD_FUNC_ARG
	}
	if *qSz < 0 || *qSz > len(q) {
		return BAD_FUNC_ARG
	}
	if len(e) == 0 || len(n) == 0 {
		return BAD_FUNC_ARG
	}

	cESz := C.word32(*eSz)
	cNSz := C.word32(*nSz)
	cDSz := C.word32(*dSz)
	cPSz := C.word32(*pSz)
	cQSz := C.word32(*qSz)

	var dPtr, pPtr, qPtr *C.uchar
	if len(d) > 0 {
		dPtr = (*C.uchar)(unsafe.Pointer(&d[0]))
	}
	if len(p) > 0 {
		pPtr = (*C.uchar)(unsafe.Pointer(&p[0]))
	}
	if len(q) > 0 {
		qPtr = (*C.uchar)(unsafe.Pointer(&q[0]))
	}

	ret := int(C.go_wc_RsaExportKey(
		key,
		(*C.uchar)(unsafe.Pointer(&e[0])), &cESz,
		(*C.uchar)(unsafe.Pointer(&n[0])), &cNSz,
		dPtr, &cDSz,
		pPtr, &cPSz,
		qPtr, &cQSz))

	if ret == 0 {
		*eSz = int(cESz)
		*nSz = int(cNSz)
		*dSz = int(cDSz)
		*pSz = int(cPSz)
		*qSz = int(cQSz)
	}
	return ret
}
