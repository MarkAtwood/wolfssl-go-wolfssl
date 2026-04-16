/* tls_seslkey.go
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
// #ifdef NO_CERTS
// static int wolfSSL_use_certificate_buffer(WOLFSSL* ssl,
//         const unsigned char* in, long sz, int format) {
//     (void)ssl; (void)in; (void)sz; (void)format;
//     return -174;
// }
// static int wolfSSL_use_PrivateKey_buffer(WOLFSSL* ssl,
//         const unsigned char* in, long sz, int format) {
//     (void)ssl; (void)in; (void)sz; (void)format;
//     return -174;
// }
// static int wolfSSL_use_certificate_chain_buffer(WOLFSSL* ssl,
//         const unsigned char* in, long sz) {
//     (void)ssl; (void)in; (void)sz;
//     return -174;
// }
// static int wolfSSL_check_private_key(const WOLFSSL* ssl) {
//     (void)ssl;
//     return -174;
// }
// #endif
// #ifdef NO_FILESYSTEM
// static int wolfSSL_use_certificate_file(WOLFSSL* ssl, const char* file,
//         int format) {
//     (void)ssl; (void)file; (void)format;
//     return -174;
// }
// static int wolfSSL_use_PrivateKey_file(WOLFSSL* ssl, const char* file,
//         int format) {
//     (void)ssl; (void)file; (void)format;
//     return -174;
// }
// static int wolfSSL_use_certificate_chain_file(WOLFSSL* ssl,
//         const char* file) {
//     (void)ssl; (void)file;
//     return -174;
// }
// #endif
import "C"
import "unsafe"

// WolfSSL_use_certificate_buffer loads a certificate from an in-memory DER or
// PEM buffer into a per-session WOLFSSL object, overriding any certificate
// previously set on the CTX for this session.
// format is SSL_FILETYPE_ASN1 (DER) or SSL_FILETYPE_PEM.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_use_certificate_buffer(ssl *C.struct_WOLFSSL, buf []byte, format int) int {
	if len(buf) == 0 {
		return -174
	}
	return int(C.wolfSSL_use_certificate_buffer(
		ssl,
		(*C.uchar)(unsafe.Pointer(&buf[0])),
		C.long(len(buf)),
		C.int(format),
	))
}

// WolfSSL_use_PrivateKey_buffer loads a private key from an in-memory DER or
// PEM buffer into a per-session WOLFSSL object.
// format is SSL_FILETYPE_ASN1 (DER) or SSL_FILETYPE_PEM.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_use_PrivateKey_buffer(ssl *C.struct_WOLFSSL, buf []byte, format int) int {
	if len(buf) == 0 {
		return -174
	}
	return int(C.wolfSSL_use_PrivateKey_buffer(
		ssl,
		(*C.uchar)(unsafe.Pointer(&buf[0])),
		C.long(len(buf)),
		C.int(format),
	))
}

// WolfSSL_use_certificate_chain_buffer loads a PEM certificate chain from an
// in-memory buffer into a per-session WOLFSSL object.
// The buffer must contain PEM-encoded certificates, leaf first.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_use_certificate_chain_buffer(ssl *C.struct_WOLFSSL, buf []byte) int {
	if len(buf) == 0 {
		return -174
	}
	return int(C.wolfSSL_use_certificate_chain_buffer(
		ssl,
		(*C.uchar)(unsafe.Pointer(&buf[0])),
		C.long(len(buf)),
	))
}

// WolfSSL_use_certificate_file loads a certificate from a file into a
// per-session WOLFSSL object.
// format is SSL_FILETYPE_ASN1 (DER) or SSL_FILETYPE_PEM.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_use_certificate_file(ssl *C.struct_WOLFSSL, file string, format int) int {
	cFile := C.CString(file)
	defer C.free(unsafe.Pointer(cFile))
	return int(C.wolfSSL_use_certificate_file(ssl, cFile, C.int(format)))
}

// WolfSSL_use_PrivateKey_file loads a private key from a file into a
// per-session WOLFSSL object.
// format is SSL_FILETYPE_ASN1 (DER) or SSL_FILETYPE_PEM.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_use_PrivateKey_file(ssl *C.struct_WOLFSSL, file string, format int) int {
	cFile := C.CString(file)
	defer C.free(unsafe.Pointer(cFile))
	return int(C.wolfSSL_use_PrivateKey_file(ssl, cFile, C.int(format)))
}

// WolfSSL_use_certificate_chain_file loads a PEM certificate chain from a file
// into a per-session WOLFSSL object.  The file must contain PEM certificates,
// leaf first.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_use_certificate_chain_file(ssl *C.struct_WOLFSSL, file string) int {
	cFile := C.CString(file)
	defer C.free(unsafe.Pointer(cFile))
	return int(C.wolfSSL_use_certificate_chain_file(ssl, cFile))
}

// WolfSSL_check_private_key verifies that the private key loaded into the
// session matches its certificate.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_check_private_key(ssl *C.struct_WOLFSSL) int {
	return int(C.wolfSSL_check_private_key(ssl))
}
