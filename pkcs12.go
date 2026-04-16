/* pkcs12.go
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
// #include <wolfssl/ssl.h>
// #include <wolfssl/wolfcrypt/pkcs12.h>
//
// /* ---- wc_PKCS12_new ------------------------------------------------------ */
//
// static WC_PKCS12* go_wc_PKCS12_new(void) {
// #ifndef NO_PKCS12
//     return wc_PKCS12_new();
// #else
//     return NULL;
// #endif
// }
//
// /* ---- wc_PKCS12_free ----------------------------------------------------- */
//
// static void go_wc_PKCS12_free(WC_PKCS12* pkcs12) {
// #ifndef NO_PKCS12
//     wc_PKCS12_free(pkcs12);
// #else
//     (void)pkcs12;
// #endif
// }
//
// /* ---- wolfSSL_PKCS12_PBE_add -------------------------------------------- */
//
// static void go_wolfSSL_PKCS12_PBE_add(void) {
// #ifdef OPENSSL_EXTRA
//     wolfSSL_PKCS12_PBE_add();
// #endif
// }
//
// /* ---- wolfSSL_d2i_PKCS12_bio -------------------------------------------- */
//
// static WC_PKCS12* go_wolfSSL_d2i_PKCS12_bio(WOLFSSL_BIO* bio,
//         WC_PKCS12** pkcs12) {
// #if defined(HAVE_PKCS12) && defined(OPENSSL_EXTRA)
//     return wolfSSL_d2i_PKCS12_bio(bio, pkcs12);
// #else
//     (void)bio; (void)pkcs12;
//     return NULL;
// #endif
// }
//
// /* ---- wolfSSL_i2d_PKCS12_bio -------------------------------------------- */
//
// static int go_wolfSSL_i2d_PKCS12_bio(WOLFSSL_BIO* bio, WC_PKCS12* pkcs12) {
// #if defined(HAVE_PKCS12) && defined(OPENSSL_EXTRA)
//     return wolfSSL_i2d_PKCS12_bio(bio, pkcs12);
// #else
//     (void)bio; (void)pkcs12;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wolfSSL_PKCS12_parse ---------------------------------------------- */
//
// static int go_wolfSSL_PKCS12_parse(WC_PKCS12* pkcs12, const char* psw,
//         WOLFSSL_EVP_PKEY** pkey, WOLFSSL_X509** cert,
//         WOLFSSL_STACK** ca) {
// #if defined(HAVE_PKCS12) && defined(OPENSSL_EXTRA)
//     return wolfSSL_PKCS12_parse(pkcs12, psw, pkey, cert,
//                                 (WOLF_STACK_OF(WOLFSSL_X509)**)ca);
// #else
//     (void)pkcs12; (void)psw; (void)pkey; (void)cert; (void)ca;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wolfSSL_PKCS12_create --------------------------------------------- */
//
// static WC_PKCS12* go_wolfSSL_PKCS12_create(char* pass, char* name,
//         WOLFSSL_EVP_PKEY* pkey, WOLFSSL_X509* cert,
//         WOLFSSL_STACK* ca,
//         int keyNID, int certNID, int itt, int macItt, int keytype) {
// #if defined(HAVE_PKCS12) && defined(OPENSSL_EXTRA)
//     return wolfSSL_PKCS12_create(pass, name, pkey, cert,
//                                  (WOLF_STACK_OF(WOLFSSL_X509)*)ca,
//                                  keyNID, certNID, itt, macItt, keytype);
// #else
//     (void)pass; (void)name; (void)pkey; (void)cert; (void)ca;
//     (void)keyNID; (void)certNID; (void)itt; (void)macItt; (void)keytype;
//     return NULL;
// #endif
// }
import "C"
import (
	"unsafe"
)

// WC_PKCS12 is the wolfcrypt PKCS#12 bundle type.
type WC_PKCS12 = C.struct_WC_PKCS12

// WOLFSSL_EVP_PKEY is the OpenSSL-compat EVP private key type.
type WOLFSSL_EVP_PKEY = C.struct_WOLFSSL_EVP_PKEY

// WolfSSL_PKCS12_new allocates and returns a new empty WC_PKCS12 object.
// Returns nil if wolfSSL was built without PKCS#12 support.
func WolfSSL_PKCS12_new() *WC_PKCS12 {
	return C.go_wc_PKCS12_new()
}

// WolfSSL_PKCS12_free frees a WC_PKCS12 object previously allocated by
// WolfSSL_PKCS12_new or returned from WolfSSL_d2i_PKCS12_bio /
// WolfSSL_PKCS12_create.
func WolfSSL_PKCS12_free(pkcs12 *WC_PKCS12) {
	C.go_wc_PKCS12_free(pkcs12)
}

// WolfSSL_PKCS12_PBE_add is a no-op compatibility stub required by some
// OpenSSL-based code that calls PKCS12_PBE_add before using PKCS#12.
// Requires wolfSSL built with OPENSSL_EXTRA.
func WolfSSL_PKCS12_PBE_add() {
	C.go_wolfSSL_PKCS12_PBE_add()
}

// WolfSSL_d2i_PKCS12_bio reads a DER-encoded PKCS#12 bundle from bio and
// returns the parsed WC_PKCS12 object. If pkcs12 is non-nil the returned
// pointer is also written there (OpenSSL convention).
//
// Returns nil on error or when wolfSSL lacks PKCS#12 support.
// Requires wolfSSL built with HAVE_PKCS12 and OPENSSL_EXTRA.
func WolfSSL_d2i_PKCS12_bio(bio *WOLFSSL_BIO, pkcs12 **WC_PKCS12) *WC_PKCS12 {
	return C.go_wolfSSL_d2i_PKCS12_bio(
		(*C.struct_WOLFSSL_BIO)(bio),
		(**C.struct_WC_PKCS12)(unsafe.Pointer(pkcs12)))
}

// WolfSSL_i2d_PKCS12_bio serialises pkcs12 to DER and writes it to bio.
//
// Returns WOLFSSL_SUCCESS (1) on success, 0 or negative on failure.
// Requires wolfSSL built with HAVE_PKCS12 and OPENSSL_EXTRA.
func WolfSSL_i2d_PKCS12_bio(bio *WOLFSSL_BIO, pkcs12 *WC_PKCS12) int {
	return int(C.go_wolfSSL_i2d_PKCS12_bio(
		(*C.struct_WOLFSSL_BIO)(bio),
		(*C.struct_WC_PKCS12)(pkcs12)))
}

// WolfSSL_PKCS12_parse decrypts pkcs12 with the given password and extracts
// the private key, end-entity certificate, and CA chain.
//
// On success pkey, cert, and ca are populated with newly-allocated objects
// that the caller must free. ca may be nil if no CA chain is wanted.
//
// Returns WOLFSSL_SUCCESS (1) on success, 0 or negative on failure.
// Requires wolfSSL built with HAVE_PKCS12 and OPENSSL_EXTRA.
func WolfSSL_PKCS12_parse(pkcs12 *WC_PKCS12, psw string,
	pkey **WOLFSSL_EVP_PKEY, cert **WOLFSSL_X509,
	ca **C.WOLFSSL_STACK) int {

	cpsw := C.CString(psw)
	defer C.free(unsafe.Pointer(cpsw))

	return int(C.go_wolfSSL_PKCS12_parse(
		(*C.struct_WC_PKCS12)(pkcs12),
		cpsw,
		(**C.struct_WOLFSSL_EVP_PKEY)(unsafe.Pointer(pkey)),
		(**C.struct_WOLFSSL_X509)(unsafe.Pointer(cert)),
		(**C.struct_WOLFSSL_STACK)(unsafe.Pointer(ca))))
}

// WolfSSL_PKCS12_create builds a PKCS#12 PFX bundle from the given private
// key, end-entity certificate, and optional CA chain, encrypted with pass.
//
// name is the friendly name embedded in the bundle (may be empty string).
// keyNID/certNID select the PBE algorithm OIDs for key and cert bags.
// itt is the key-bag iteration count; macItt is the MAC iteration count.
// keytype is the key type flag (0 = default).
//
// Returns a newly allocated WC_PKCS12 on success, or nil on failure.
// Requires wolfSSL built with HAVE_PKCS12 and OPENSSL_EXTRA.
func WolfSSL_PKCS12_create(pass string, name string,
	pkey *WOLFSSL_EVP_PKEY, cert *WOLFSSL_X509,
	ca *C.WOLFSSL_STACK,
	keyNID int, certNID int, itt int, macItt int, keytype int) *WC_PKCS12 {

	cpass := C.CString(pass)
	defer C.free(unsafe.Pointer(cpass))
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	return C.go_wolfSSL_PKCS12_create(
		cpass, cname,
		(*C.struct_WOLFSSL_EVP_PKEY)(unsafe.Pointer(pkey)),
		(*C.struct_WOLFSSL_X509)(unsafe.Pointer(cert)),
		(*C.struct_WOLFSSL_STACK)(unsafe.Pointer(ca)),
		C.int(keyNID), C.int(certNID), C.int(itt), C.int(macItt), C.int(keytype))
}
