/* x509_cert.go
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
// typedef struct Cert {} Cert;
// static int wc_InitCert(Cert* cert) { (void)cert; return -174; }
// static int go_wc_MakeCert_ex(Cert* cert, unsigned char* buf, unsigned int bufsz,
//                               int keyType, void* key, WC_RNG* rng)
//     { (void)cert; (void)buf; (void)bufsz; (void)keyType; (void)key; (void)rng; return -174; }
// static int wc_SetIssuer(Cert* cert, const char* issuerFile)
//     { (void)cert; (void)issuerFile; return -174; }
// static int wc_SetSubject(Cert* cert, const char* subjectFile)
//     { (void)cert; (void)subjectFile; return -174; }
// static int go_wc_SetDaysValid(Cert* cert, int days)
//     { (void)cert; (void)days; return -174; }
// static int wc_SetIssuerBuffer(Cert* cert, const unsigned char* der, int derSz)
//     { (void)cert; (void)der; (void)derSz; return -174; }
// static int wc_SetSubjectBuffer(Cert* cert, const unsigned char* der, int derSz)
//     { (void)cert; (void)der; (void)derSz; return -174; }
// #else
// static int go_wc_MakeCert_ex(Cert* cert, unsigned char* buf, unsigned int bufsz,
//                               int keyType, void* key, WC_RNG* rng) {
//     return wc_MakeCert_ex(cert, buf, bufsz, keyType, key, rng);
// }
// static int go_wc_SetDaysValid(Cert* cert, int days) {
//     cert->daysValid = days;
//     return 0;
// }
// #endif
// #if !defined(WOLFSSL_CERT_GEN) || !defined(WOLFSSL_ALT_NAMES)
// static int wc_SetAltNames(Cert* cert, const char* file)
//     { (void)cert; (void)file; return -174; }
// static int wc_SetAltNamesBuffer(Cert* cert, const unsigned char* der, int derSz)
//     { (void)cert; (void)der; (void)derSz; return -174; }
// #endif
import "C"
import "unsafe"

// Cert is the wolfcrypt certificate generation struct.
type Cert = C.struct_Cert

// Wc_InitCert initializes a Cert struct with default values.
// Returns 0 on success, negative on error.
func Wc_InitCert(cert *Cert) int {
	return int(C.wc_InitCert(cert))
}

// Wc_MakeCert_ex creates a DER-encoded certificate from cert using a generic
// key type. keyType is one of the CTC_* key type constants (e.g. ECDSAk, RSAk).
// Returns the number of bytes written into buf on success, negative on error.
func Wc_MakeCert_ex(cert *Cert, buf []byte, bufSz int, keyType int, key unsafe.Pointer, rng *WC_RNG) int {
	if bufSz < 0 || bufSz > len(buf) || len(buf) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_MakeCert_ex(cert, (*C.uchar)(unsafe.Pointer(&buf[0])),
		C.uint(bufSz), C.int(keyType), key, rng))
}

// Wc_SetIssuer sets the issuer fields of cert from a DER certificate file at
// issuerFile. Returns 0 on success, negative on error.
func Wc_SetIssuer(cert *Cert, issuerFile string) int {
	cStr := C.CString(issuerFile)
	defer C.free(unsafe.Pointer(cStr))
	return int(C.wc_SetIssuer(cert, cStr))
}

// Wc_SetSubject sets the subject fields of cert from a DER certificate file at
// subjectFile. Returns 0 on success, negative on error.
func Wc_SetSubject(cert *Cert, subjectFile string) int {
	cStr := C.CString(subjectFile)
	defer C.free(unsafe.Pointer(cStr))
	return int(C.wc_SetSubject(cert, cStr))
}

// Wc_SetAltNames sets the subject alternative names of cert from a DER
// certificate file. Requires WOLFSSL_ALT_NAMES at build time.
// Returns 0 on success, negative on error.
func Wc_SetAltNames(cert *Cert, altFile string) int {
	cStr := C.CString(altFile)
	defer C.free(unsafe.Pointer(cStr))
	return int(C.wc_SetAltNames(cert, cStr))
}

// Wc_SetDaysValid sets the daysValid field of cert directly.
// Returns 0 on success, negative on error.
func Wc_SetDaysValid(cert *Cert, days int) int {
	return int(C.go_wc_SetDaysValid(cert, C.int(days)))
}

// Wc_SetIssuerBuffer sets the issuer of cert from a DER-encoded certificate
// buffer. Returns 0 on success, negative on error.
func Wc_SetIssuerBuffer(cert *Cert, der []byte, derSz int) int {
	if derSz < 0 || derSz > len(der) || len(der) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.wc_SetIssuerBuffer(cert, (*C.uchar)(unsafe.Pointer(&der[0])), C.int(derSz)))
}

// Wc_SetSubjectBuffer sets the subject of cert from a DER-encoded certificate
// buffer. Returns 0 on success, negative on error.
func Wc_SetSubjectBuffer(cert *Cert, der []byte, derSz int) int {
	if derSz < 0 || derSz > len(der) || len(der) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.wc_SetSubjectBuffer(cert, (*C.uchar)(unsafe.Pointer(&der[0])), C.int(derSz)))
}

// Wc_SetAltNamesBuffer sets the subject alternative names of cert from a
// DER-encoded certificate buffer. Requires WOLFSSL_ALT_NAMES at build time.
// Returns 0 on success, negative on error.
func Wc_SetAltNamesBuffer(cert *Cert, der []byte, derSz int) int {
	if derSz < 0 || derSz > len(der) || len(der) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.wc_SetAltNamesBuffer(cert, (*C.uchar)(unsafe.Pointer(&der[0])), C.int(derSz)))
}
