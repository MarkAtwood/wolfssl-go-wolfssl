/* tls_info.go
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
// #include <stdlib.h>
import "C"
import (
	"unsafe"
)

// WolfSSL_get_cipher returns the cipher name for the current TLS connection.
// This is an alias for wolfSSL_get_cipher_name.
func WolfSSL_get_cipher(ssl *C.struct_WOLFSSL) string {
	return C.GoString(C.wolfSSL_get_cipher(ssl))
}

// WolfSSL_get_cipher_list returns a comma-separated list of available ciphers
// at the given priority index. Returns an empty string when the list is exhausted.
func WolfSSL_get_cipher_list(priority int) string {
	cs := C.wolfSSL_get_cipher_list(C.int(priority))
	if cs == nil {
		return ""
	}
	return C.GoString(cs)
}

// WolfSSL_get_ciphers fills buf with a colon-separated list of all supported
// cipher suite names. Returns WOLFSSL_SUCCESS (1) on success.
func WolfSSL_get_ciphers(buf []byte) int {
	if len(buf) == 0 {
		return -1
	}
	return int(C.wolfSSL_get_ciphers((*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf))))
}

// WolfSSL_get_curve_name returns the name of the elliptic curve used in the
// current TLS connection's key exchange.
func WolfSSL_get_curve_name(ssl *C.struct_WOLFSSL) string {
	cs := C.wolfSSL_get_curve_name(ssl)
	if cs == nil {
		return ""
	}
	return C.GoString(cs)
}

// WolfSSL_get_current_cipher returns the WOLFSSL_CIPHER object for the
// cipher suite currently in use.
func WolfSSL_get_current_cipher(ssl *C.struct_WOLFSSL) *C.struct_WOLFSSL_CIPHER {
	return C.wolfSSL_get_current_cipher(ssl)
}

// WolfSSL_CIPHER_get_name returns the name of the given cipher suite.
func WolfSSL_CIPHER_get_name(cipher *C.struct_WOLFSSL_CIPHER) string {
	cs := C.wolfSSL_CIPHER_get_name(cipher)
	if cs == nil {
		return ""
	}
	return C.GoString(cs)
}

// WolfSSL_get_peer_certificate returns the peer's X.509 certificate from the
// TLS session. The caller is responsible for freeing the returned certificate
// with wolfSSL_X509_free.
func WolfSSL_get_peer_certificate(ssl *C.struct_WOLFSSL) *C.struct_WOLFSSL_X509 {
	return C.wolfSSL_get_peer_certificate(ssl)
}

// WolfSSL_GetSide returns whether the session is on the client or server side.
// Returns WOLFSSL_CLIENT_END (1) or WOLFSSL_SERVER_END (0).
func WolfSSL_GetSide(ssl *C.struct_WOLFSSL) int {
	return int(C.wolfSSL_GetSide(ssl))
}

// WolfSSL_GetKeySize returns the key size in bytes for the current cipher.
func WolfSSL_GetKeySize(ssl *C.struct_WOLFSSL) int {
	return int(C.wolfSSL_GetKeySize(ssl))
}

// WolfSSL_GetBulkCipher returns an identifier for the bulk cipher algorithm
// in use (e.g., wolfssl_aes, wolfssl_chacha).
func WolfSSL_GetBulkCipher(ssl *C.struct_WOLFSSL) int {
	return int(C.wolfSSL_GetBulkCipher(ssl))
}
