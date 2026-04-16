/* tls_reneg.go
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
// #if !defined(HAVE_SECURE_RENEGOTIATION) && !defined(HAVE_SERVER_RENEGOTIATION_INFO)
// static int wolfSSL_UseSecureRenegotiation(WOLFSSL* ssl) { (void)ssl; return -174; }
// static int wolfSSL_CTX_UseSecureRenegotiation(WOLFSSL_CTX* ctx) { (void)ctx; return -174; }
// #endif
// #ifndef HAVE_SECURE_RENEGOTIATION
// static int wolfSSL_Rehandshake(WOLFSSL* ssl) { (void)ssl; return -174; }
// static int wolfSSL_SecureResume(WOLFSSL* ssl) { (void)ssl; return -174; }
// #endif
import "C"

// WolfSSL_CTX_UseSecureRenegotiation enables secure renegotiation (RFC 5746)
// for all sessions created from ctx. Returns WOLFSSL_SUCCESS (1) on success.
// Returns -174 if the feature was not compiled in.
func WolfSSL_CTX_UseSecureRenegotiation(ctx *C.struct_WOLFSSL_CTX) int {
	return int(C.wolfSSL_CTX_UseSecureRenegotiation(ctx))
}

// WolfSSL_UseSecureRenegotiation enables secure renegotiation (RFC 5746)
// for a single TLS session. Returns WOLFSSL_SUCCESS (1) on success.
// Returns -174 if the feature was not compiled in.
func WolfSSL_UseSecureRenegotiation(ssl *C.struct_WOLFSSL) int {
	return int(C.wolfSSL_UseSecureRenegotiation(ssl))
}

// WolfSSL_Rehandshake initiates a TLS renegotiation handshake on an existing
// connection. Requires HAVE_SECURE_RENEGOTIATION.
// Returns WOLFSSL_SUCCESS (1) on success, -174 if not compiled in.
func WolfSSL_Rehandshake(ssl *C.struct_WOLFSSL) int {
	return int(C.wolfSSL_Rehandshake(ssl))
}

// WolfSSL_SecureResume performs a secure session resumption with renegotiation.
// Requires HAVE_SECURE_RENEGOTIATION.
// Returns WOLFSSL_SUCCESS (1) on success, -174 if not compiled in.
func WolfSSL_SecureResume(ssl *C.struct_WOLFSSL) int {
	return int(C.wolfSSL_SecureResume(ssl))
}

// WolfSSL_CTX_DisableExtendedMasterSecret disables the Extended Master Secret
// extension (RFC 7627) for all sessions created from ctx.
// Returns WOLFSSL_SUCCESS (1) on success.
func WolfSSL_CTX_DisableExtendedMasterSecret(ctx *C.struct_WOLFSSL_CTX) int {
	return int(C.wolfSSL_CTX_DisableExtendedMasterSecret(ctx))
}

// WolfSSL_DisableExtendedMasterSecret disables the Extended Master Secret
// extension (RFC 7627) for a single TLS session.
// Returns WOLFSSL_SUCCESS (1) on success.
func WolfSSL_DisableExtendedMasterSecret(ssl *C.struct_WOLFSSL) int {
	return int(C.wolfSSL_DisableExtendedMasterSecret(ssl))
}
