/* tls_tickets.go
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
// #ifndef HAVE_SESSION_TICKET
// int wolfSSL_CTX_UseSessionTicket(WOLFSSL_CTX* ctx) {
//     return -174;
// }
// typedef int (*ticketCompatCb)();
// int wolfSSL_CTX_set_tlsext_ticket_key_cb(WOLFSSL_CTX* ctx, ticketCompatCb cb) {
//     return -174;
// }
// typedef int (*SessionTicketEncCb)();
// int wolfSSL_CTX_set_TicketEncCb(WOLFSSL_CTX* ctx, SessionTicketEncCb cb) {
//     return -174;
// }
// #endif /* !HAVE_SESSION_TICKET */
// #ifdef NO_SESSION_CACHE
// WOLFSSL_SESSION* wolfSSL_get_session(WOLFSSL* ssl) {
//     return (WOLFSSL_SESSION*)0;
// }
// int wolfSSL_set_session(WOLFSSL* ssl, WOLFSSL_SESSION* session) {
//     return -174;
// }
// void wolfSSL_SESSION_free(WOLFSSL_SESSION* session) {}
// int wolfSSL_i2d_SSL_SESSION(WOLFSSL_SESSION* sess, unsigned char** p) {
//     return -174;
// }
// WOLFSSL_SESSION* wolfSSL_d2i_SSL_SESSION(WOLFSSL_SESSION** sess,
//                                          const unsigned char** p, long i) {
//     return (WOLFSSL_SESSION*)0;
// }
// #endif /* NO_SESSION_CACHE */
import "C"
import "unsafe"

// WOLFSSL_SESSION is the Go type alias for a wolfSSL TLS session object.
type WOLFSSL_SESSION = C.struct_WOLFSSL_SESSION

// WolfSSL_CTX_UseSessionTicket enables TLS session ticket support on the
// context. Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_CTX_UseSessionTicket(ctx *C.struct_WOLFSSL_CTX) int {
	return int(C.wolfSSL_CTX_UseSessionTicket(ctx))
}

// WolfSSL_CTX_set_tlsext_ticket_key_cb installs an OpenSSL-compatible session
// ticket key callback (ticketCompatCb). The callback receives name, iv,
// cipher ctx, and HMAC ctx pointers, plus an enc flag.
// cb must be a C function pointer of the correct type; pass nil to clear.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_CTX_set_tlsext_ticket_key_cb(ctx *C.struct_WOLFSSL_CTX, cb unsafe.Pointer) int {
	return int(C.wolfSSL_CTX_set_tlsext_ticket_key_cb(ctx, (C.ticketCompatCb)(cb)))
}

// WolfSSL_CTX_set_TicketEncCb installs a wolfSSL-native session ticket
// encryption/decryption callback (SessionTicketEncCb).
// cb must be a C function pointer of the correct type; pass nil to clear.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_CTX_set_TicketEncCb(ctx *C.struct_WOLFSSL_CTX, cb unsafe.Pointer) int {
	return int(C.wolfSSL_CTX_set_TicketEncCb(ctx, (C.SessionTicketEncCb)(cb)))
}

// WolfSSL_CTX_set_session_cache_mode sets the session cache mode flags on the
// context. mode is a bitmask of SSL_SESS_CACHE_* constants.
// Returns the previously set mode.
func WolfSSL_CTX_set_session_cache_mode(ctx *C.struct_WOLFSSL_CTX, mode int) int {
	return int(C.wolfSSL_CTX_set_session_cache_mode(ctx, C.long(mode)))
}

// WolfSSL_get_session retrieves the current session object from ssl.
// The returned pointer is owned by the ssl object and must not be freed.
// Returns nil if no session is available.
func WolfSSL_get_session(ssl *C.struct_WOLFSSL) *C.struct_WOLFSSL_SESSION {
	return C.wolfSSL_get_session(ssl)
}

// WolfSSL_set_session resumes a previously obtained session on ssl.
// session must have been obtained from WolfSSL_get_session on a completed
// handshake. Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_set_session(ssl *C.struct_WOLFSSL, session *C.struct_WOLFSSL_SESSION) int {
	return int(C.wolfSSL_set_session(ssl, session))
}

// WolfSSL_SESSION_free releases a WOLFSSL_SESSION.
// Call this only on sessions obtained from WolfSSL_d2i_SSL_SESSION or
// wolfSSL_get1_session (which increment the reference count).
// Sessions obtained from WolfSSL_get_session are owned by the ssl object —
// do not free them.
func WolfSSL_SESSION_free(session *C.struct_WOLFSSL_SESSION) {
	C.wolfSSL_SESSION_free(session)
}

// WolfSSL_i2d_SSL_SESSION serializes session to DER. If p is non-nil, the
// encoded bytes are written there and *p is advanced past the written data.
// Returns the number of bytes written, or negative on error.
func WolfSSL_i2d_SSL_SESSION(sess *C.struct_WOLFSSL_SESSION, p *[]byte) int {
	if p == nil {
		return int(C.wolfSSL_i2d_SSL_SESSION(sess, (**C.uchar)(nil)))
	}
	var cp *C.uchar
	if len(*p) > 0 {
		cp = (*C.uchar)(unsafe.Pointer(&(*p)[0]))
	}
	ret := int(C.wolfSSL_i2d_SSL_SESSION(sess, &cp))
	// Advance *p past the bytes written, matching the OpenSSL i2d convention.
	if ret > 0 && len(*p) >= ret {
		*p = (*p)[ret:]
	}
	return ret
}

// WolfSSL_d2i_SSL_SESSION deserializes a DER-encoded session. If sess is
// non-nil, the result is stored there (and any previous session freed).
// p is advanced past the consumed bytes. i is the length of the buffer.
// Returns the deserialized session on success, nil on error.
// The caller is responsible for calling WolfSSL_SESSION_free on the result.
func WolfSSL_d2i_SSL_SESSION(sess **C.struct_WOLFSSL_SESSION,
	p *[]byte, i int) *C.struct_WOLFSSL_SESSION {
	if p == nil || len(*p) == 0 {
		return nil
	}
	start := unsafe.Pointer(&(*p)[0])
	cp := (*C.uchar)(start)
	result := C.wolfSSL_d2i_SSL_SESSION(sess, &cp, C.long(i))
	// Advance *p past the bytes consumed, matching the OpenSSL d2i convention.
	if result != nil && cp != nil {
		consumed := int(uintptr(unsafe.Pointer(cp)) - uintptr(start))
		if consumed > 0 && consumed <= len(*p) {
			*p = (*p)[consumed:]
		}
	}
	return result
}
