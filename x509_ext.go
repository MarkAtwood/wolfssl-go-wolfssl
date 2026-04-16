/* x509_ext.go
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
// #include <wolfssl/openssl/x509.h>
// #include <wolfssl/openssl/x509v3.h>
// #include <wolfssl/openssl/asn1.h>
// #ifndef OPENSSL_EXTRA
// typedef struct WOLFSSL_X509_EXTENSION {} WOLFSSL_X509_EXTENSION;
// typedef struct WOLFSSL_ASN1_STRING {} WOLFSSL_ASN1_STRING;
// static int wolfSSL_X509_get_ext_count(const WOLFSSL_X509* x509)
//     { (void)x509; return -174; }
// static WOLFSSL_X509_EXTENSION* wolfSSL_X509_get_ext(const WOLFSSL_X509* x, int loc)
//     { (void)x; (void)loc; return NULL; }
// static WOLFSSL_ASN1_OBJECT* wolfSSL_X509_EXTENSION_get_object(WOLFSSL_X509_EXTENSION* ext)
//     { (void)ext; return NULL; }
// static WOLFSSL_ASN1_STRING* wolfSSL_X509_EXTENSION_get_data(WOLFSSL_X509_EXTENSION* ext)
//     { (void)ext; return NULL; }
// static int wolfSSL_X509_EXTENSION_get_critical(const WOLFSSL_X509_EXTENSION* ex)
//     { (void)ex; return -174; }
// static void wolfSSL_X509_EXTENSION_free(WOLFSSL_X509_EXTENSION* ext)
//     { (void)ext; }
// static void* wolfSSL_X509_get_ext_d2i(const WOLFSSL_X509* x509, int nid, int* c, int* idx)
//     { (void)x509; (void)nid; (void)c; (void)idx; return NULL; }
// #endif
import "C"
import "unsafe"

// WOLFSSL_X509_EXTENSION is the wolfSSL X.509 extension struct.
type WOLFSSL_X509_EXTENSION = C.struct_WOLFSSL_X509_EXTENSION

// WOLFSSL_ASN1_STRING is the wolfSSL ASN.1 octet/string data struct.
type WOLFSSL_ASN1_STRING = C.struct_WOLFSSL_ASN1_STRING

// WolfSSL_X509_get_ext_count returns the number of extensions in x509.
// Requires OPENSSL_EXTRA at build time.
// Returns the extension count on success, negative on error.
func WolfSSL_X509_get_ext_count(x509 *WOLFSSL_X509) int {
	return int(C.wolfSSL_X509_get_ext_count(x509))
}

// WolfSSL_X509_get_ext returns the extension at index loc from x509.
// Requires OPENSSL_EXTRA at build time.
// Returns a pointer to the extension on success, nil if not found.
func WolfSSL_X509_get_ext(x509 *WOLFSSL_X509, loc int) *WOLFSSL_X509_EXTENSION {
	return C.wolfSSL_X509_get_ext(x509, C.int(loc))
}

// WolfSSL_X509_EXTENSION_get_object returns the OID object from ext.
// Returns a pointer to the ASN1_OBJECT on success, nil on error.
func WolfSSL_X509_EXTENSION_get_object(ext *WOLFSSL_X509_EXTENSION) *WOLFSSL_ASN1_OBJECT {
	return C.wolfSSL_X509_EXTENSION_get_object(ext)
}

// WolfSSL_X509_EXTENSION_get_data returns the raw data of ext as an
// ASN1_STRING. The returned pointer is owned by ext and must not be freed.
func WolfSSL_X509_EXTENSION_get_data(ext *WOLFSSL_X509_EXTENSION) *WOLFSSL_ASN1_STRING {
	return C.wolfSSL_X509_EXTENSION_get_data(ext)
}

// WolfSSL_X509_EXTENSION_get_critical returns the criticality flag of ext.
// Returns 1 if critical, 0 if not, negative on error.
func WolfSSL_X509_EXTENSION_get_critical(ext *WOLFSSL_X509_EXTENSION) int {
	return int(C.wolfSSL_X509_EXTENSION_get_critical(ext))
}

// WolfSSL_X509_EXTENSION_free frees an extension previously obtained via
// WolfSSL_X509_get_ext or similar calls that transfer ownership.
func WolfSSL_X509_EXTENSION_free(ext *WOLFSSL_X509_EXTENSION) {
	C.wolfSSL_X509_EXTENSION_free(ext)
}

// WolfSSL_X509_get_ext_d2i decodes an extension from x509 identified by nid
// into its native Go-accessible form. c and idx are optional out-parameters
// (pass nil to ignore). Returns the decoded value as unsafe.Pointer on success,
// nil on error. Requires OPENSSL_EXTRA or WOLFSSL_WPAS_SMALL at build time.
func WolfSSL_X509_get_ext_d2i(x509 *WOLFSSL_X509, nid int, c *int, idx *int) unsafe.Pointer {
	var cC C.int
	var cIdx C.int
	var cCPtr *C.int
	var cIdxPtr *C.int
	if c != nil {
		cCPtr = &cC
	}
	if idx != nil {
		cIdxPtr = &cIdx
	}
	result := C.wolfSSL_X509_get_ext_d2i(x509, C.int(nid), cCPtr, cIdxPtr)
	if c != nil {
		*c = int(cC)
	}
	if idx != nil {
		*idx = int(cIdx)
	}
	return result
}
