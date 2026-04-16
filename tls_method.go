/* tls_method.go
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
// #ifdef NO_WOLFSSL_CLIENT
// WOLFSSL_METHOD* wolfSSLv23_client_method(void) { return NULL; }
// WOLFSSL_METHOD* wolfTLS_client_method(void)    { return NULL; }
// WOLFSSL_METHOD* wolfDTLS_client_method(void)   { return NULL; }
// #endif /* NO_WOLFSSL_CLIENT */
// #ifdef NO_WOLFSSL_SERVER
// WOLFSSL_METHOD* wolfSSLv23_server_method(void) { return NULL; }
// WOLFSSL_METHOD* wolfTLS_server_method(void)    { return NULL; }
// WOLFSSL_METHOD* wolfDTLS_server_method(void)   { return NULL; }
// #endif /* NO_WOLFSSL_SERVER */
// #ifndef WOLFSSL_DTLS
// WOLFSSL_METHOD* wolfDTLS_client_method(void) { return NULL; }
// WOLFSSL_METHOD* wolfDTLS_server_method(void) { return NULL; }
// #endif /* WOLFSSL_DTLS */
import "C"

// WolfSSLv23_client_method returns a WOLFSSL_METHOD for a TLS client that
// auto-negotiates the highest mutually supported TLS version.
func WolfSSLv23_client_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfSSLv23_client_method()
}

// WolfSSLv23_server_method returns a WOLFSSL_METHOD for a TLS server that
// auto-negotiates the highest mutually supported TLS version.
func WolfSSLv23_server_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfSSLv23_server_method()
}

// WolfSSLv23_method returns a WOLFSSL_METHOD for auto-negotiated TLS (both
// client and server roles).
func WolfSSLv23_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfSSLv23_method()
}

// WolfTLS_client_method returns a WOLFSSL_METHOD for a TLS client using the
// wolfSSL native TLS stack (equivalent to wolfSSLv23_client_method).
func WolfTLS_client_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfTLS_client_method()
}

// WolfTLS_server_method returns a WOLFSSL_METHOD for a TLS server using the
// wolfSSL native TLS stack (equivalent to wolfSSLv23_server_method).
func WolfTLS_server_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfTLS_server_method()
}

// WolfDTLS_client_method returns a WOLFSSL_METHOD for a DTLS client that
// auto-negotiates the DTLS version.  Returns nil if WOLFSSL_DTLS is not
// compiled in.
func WolfDTLS_client_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfDTLS_client_method()
}

// WolfDTLS_server_method returns a WOLFSSL_METHOD for a DTLS server that
// auto-negotiates the DTLS version.  Returns nil if WOLFSSL_DTLS is not
// compiled in.
func WolfDTLS_server_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfDTLS_server_method()
}
