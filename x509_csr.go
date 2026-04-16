/* x509_csr.go
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
// #include <wolfssl/wolfcrypt/asn_public.h>
// #include <wolfssl/wolfcrypt/random.h>
// #include <wolfssl/wolfcrypt/rsa.h>
// #include <wolfssl/wolfcrypt/ecc.h>
// #ifndef WOLFSSL_CERT_GEN
// static int wc_SignCert_ex(int requestSz, int sType, unsigned char* buf,
//                           unsigned int buffSz, int keyType, void* key,
//                           WC_RNG* rng)
//     { (void)requestSz; (void)sType; (void)buf; (void)buffSz;
//       (void)keyType; (void)key; (void)rng; return -174; }
// static int wc_MakeSelfCert(Cert* cert, unsigned char* buf, unsigned int buffSz,
//                             RsaKey* key, WC_RNG* rng)
//     { (void)cert; (void)buf; (void)buffSz; (void)key; (void)rng; return -174; }
// #endif
// #if !defined(WOLFSSL_CERT_GEN) || !defined(WOLFSSL_CERT_REQ)
// static int wc_MakeCertReq_ex(Cert* cert, unsigned char* derBuffer,
//                               unsigned int derSz, int keyType, void* key)
//     { (void)cert; (void)derBuffer; (void)derSz; (void)keyType; (void)key; return -174; }
// #endif
import "C"
import "unsafe"

// Wc_MakeCertReq_ex creates a DER-encoded certificate signing request (CSR)
// from cert using a generic key type. keyType is one of the CTC_* key type
// constants (e.g. ECDSAk, RSAk). Requires WOLFSSL_CERT_REQ at build time.
// Returns the number of bytes written into derBuffer on success, negative on error.
func Wc_MakeCertReq_ex(cert *Cert, derBuffer []byte, derSz int, keyType int, key unsafe.Pointer) int {
	if derSz < 0 || derSz > len(derBuffer) || len(derBuffer) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.wc_MakeCertReq_ex(cert, (*C.uchar)(unsafe.Pointer(&derBuffer[0])),
		C.uint(derSz), C.int(keyType), key))
}

// Wc_SignCert_ex signs a DER-encoded certificate or CSR in buf using a generic
// key type. requestSz is the number of bytes in buf from a prior MakeCert or
// MakeCertReq call. sType is the signature algorithm (e.g. CTC_SHA256wECDSA).
// keyType is one of the CTC_* key type constants. buffSz is the total capacity
// of buf. Returns the final DER size on success, negative on error.
func Wc_SignCert_ex(requestSz int, sType int, buf []byte, buffSz int, keyType int, key unsafe.Pointer, rng *WC_RNG) int {
	if buffSz < 0 || buffSz > len(buf) || len(buf) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.wc_SignCert_ex(C.int(requestSz), C.int(sType),
		(*C.uchar)(unsafe.Pointer(&buf[0])), C.uint(buffSz),
		C.int(keyType), key, rng))
}

// Wc_MakeSelfCert combines wc_MakeCert and wc_SignCert into a single call that
// produces a self-signed RSA certificate. Returns the final DER size on success,
// negative on error.
func Wc_MakeSelfCert(cert *Cert, buf []byte, buffSz int, key *RsaKey, rng *WC_RNG) int {
	if buffSz < 0 || buffSz > len(buf) || len(buf) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.wc_MakeSelfCert(cert, (*C.uchar)(unsafe.Pointer(&buf[0])),
		C.uint(buffSz), key, rng))
}
