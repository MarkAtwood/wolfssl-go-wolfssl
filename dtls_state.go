/* dtls_state.go
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
//
// /* wolfSSL_dtls_export, wolfSSL_dtls_import, wolfSSL_CTX_dtls_set_export,
//    and the wc_dtls_export callback typedef are gated on both
//    WOLFSSL_SESSION_EXPORT and WOLFSSL_DTLS.  wolfSSL_dtls_get_peer,
//    wolfSSL_dtls_set_peer are always declared (outside those guards).
//    wolfSSL_CTX_dtls_set_sctp requires WOLFSSL_DTLS && WOLFSSL_SCTP. */
//
// /* ---- wolfSSL_dtls_export ------------------------------------------------ */
//
// static int go_wolfSSL_dtls_export(WOLFSSL* ssl, unsigned char* buf,
//         unsigned int* sz) {
// #if defined(WOLFSSL_DTLS) && defined(WOLFSSL_SESSION_EXPORT)
//     return wolfSSL_dtls_export(ssl, buf, sz);
// #else
//     (void)ssl; (void)buf; (void)sz;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wolfSSL_dtls_export_state_only ------------------------------------- */
//
// static int go_wolfSSL_dtls_export_state_only(WOLFSSL* ssl, unsigned char* buf,
//         unsigned int* sz) {
// #if defined(WOLFSSL_DTLS) && defined(WOLFSSL_SESSION_EXPORT)
//     return wolfSSL_dtls_export_state_only(ssl, buf, sz);
// #else
//     (void)ssl; (void)buf; (void)sz;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wolfSSL_dtls_import ------------------------------------------------ */
//
// static int go_wolfSSL_dtls_import(WOLFSSL* ssl, const unsigned char* buf,
//         unsigned int sz) {
// #if defined(WOLFSSL_DTLS) && defined(WOLFSSL_SESSION_EXPORT)
//     return wolfSSL_dtls_import(ssl, buf, sz);
// #else
//     (void)ssl; (void)buf; (void)sz;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wolfSSL_CTX_dtls_set_export --------------------------------------- */
//
// /* wc_dtls_export is only typedef'd inside WOLFSSL_SESSION_EXPORT &&
//    WOLFSSL_DTLS in ssl.h.  Use void* as the parameter type so the shim
//    compiles regardless; the cast to wc_dtls_export happens inside the
//    guarded branch where the type is guaranteed to be visible. */
// static int go_wolfSSL_CTX_dtls_set_export(WOLFSSL_CTX* ctx, void* fn) {
// #if defined(WOLFSSL_DTLS) && defined(WOLFSSL_SESSION_EXPORT)
//     return wolfSSL_CTX_dtls_set_export(ctx, (wc_dtls_export)fn);
// #else
//     (void)ctx; (void)fn;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wolfSSL_dtls_get_peer --------------------------------------------- */
//
// static int go_wolfSSL_dtls_get_peer(WOLFSSL* ssl, void* peer,
//         unsigned int* peerSz) {
// #ifdef WOLFSSL_DTLS
//     return wolfSSL_dtls_get_peer(ssl, peer, peerSz);
// #else
//     (void)ssl; (void)peer; (void)peerSz;
//     return NOT_COMPILED_IN;
// #endif
// }
//
//
// /* ---- wolfSSL_CTX_dtls_set_sctp ----------------------------------------- */
//
// static int go_wolfSSL_CTX_dtls_set_sctp(WOLFSSL_CTX* ctx) {
// #if defined(WOLFSSL_DTLS) && defined(WOLFSSL_SCTP)
//     return wolfSSL_CTX_dtls_set_sctp(ctx);
// #else
//     (void)ctx;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wolfSSL_dtls_get_current_timeout ---------------------------------- */
//
// static int go_wolfSSL_dtls_get_current_timeout(WOLFSSL* ssl) {
// #ifdef WOLFSSL_DTLS
//     return wolfSSL_dtls_get_current_timeout(ssl);
// #else
//     (void)ssl;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wolfSSL_dtls_set_timeout_init ------------------------------------- */
//
// static int go_wolfSSL_dtls_set_timeout_init(WOLFSSL* ssl, int timeout) {
// #ifdef WOLFSSL_DTLS
//     return wolfSSL_dtls_set_timeout_init(ssl, timeout);
// #else
//     (void)ssl; (void)timeout;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wolfSSL_dtls_set_timeout_max -------------------------------------- */
//
// static int go_wolfSSL_dtls_set_timeout_max(WOLFSSL* ssl, int timeout) {
// #ifdef WOLFSSL_DTLS
//     return wolfSSL_dtls_set_timeout_max(ssl, timeout);
// #else
//     (void)ssl; (void)timeout;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wolfSSL_dtls_got_timeout ------------------------------------------ */
//
// static int go_wolfSSL_dtls_got_timeout(WOLFSSL* ssl) {
// #ifdef WOLFSSL_DTLS
//     return wolfSSL_dtls_got_timeout(ssl);
// #else
//     (void)ssl;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wolfSSL_dtls_retransmit ------------------------------------------- */
//
// static int go_wolfSSL_dtls_retransmit(WOLFSSL* ssl) {
// #ifdef WOLFSSL_DTLS
//     return wolfSSL_dtls_retransmit(ssl);
// #else
//     (void)ssl;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wolfSSL_DTLS_SetCookieSecret -------------------------------------- */
//
// static int go_wolfSSL_DTLS_SetCookieSecret(WOLFSSL* ssl,
//         const unsigned char* secret, unsigned int secretSz) {
// #if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_SERVER)
//     return wolfSSL_DTLS_SetCookieSecret(ssl, secret, (word32)secretSz);
// #else
//     (void)ssl; (void)secret; (void)secretSz;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wolfDTLS_accept_stateless ----------------------------------------- */
//
// static int go_wolfDTLS_accept_stateless(WOLFSSL* ssl) {
// #if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_SERVER)
//     return wolfDTLS_accept_stateless(ssl);
// #else
//     (void)ssl;
//     return NOT_COMPILED_IN;
// #endif
// }
import "C"
import (
	"unsafe"
)

// WolfSSL_dtls_export serialises the full DTLS session state of ssl into buf.
// On entry *sz must hold the capacity of buf in bytes; on success *sz is
// updated to the number of bytes written.
//
// Pass buf as nil and *sz as 0 to perform a size probe: wolfSSL returns 0
// and sets *sz to the required buffer size (MAX_EXPORT_BUFFER).
//
// Returns the number of bytes written (positive) on success, negative error
// code on failure.
// Requires wolfSSL built with WOLFSSL_DTLS and WOLFSSL_SESSION_EXPORT.
func WolfSSL_dtls_export(ssl *WOLFSSL, buf []byte, sz *int) int {
	if sz == nil {
		return BAD_FUNC_ARG
	}
	var bufPtr *C.uchar
	if len(buf) > 0 {
		bufPtr = (*C.uchar)(unsafe.Pointer(&buf[0]))
	}
	cSz := C.uint(*sz)
	ret := int(C.go_wolfSSL_dtls_export((*C.struct_WOLFSSL)(ssl), bufPtr, &cSz))
	*sz = int(cSz)
	return ret
}

// WolfSSL_dtls_export_state_only serialises only the lightweight DTLS state
// (epoch, sequence numbers, and AEAD keys) of ssl into buf. This is a subset
// of the full export produced by WolfSSL_dtls_export and results in a smaller
// buffer.
//
// On entry *sz must hold the capacity of buf in bytes; on success *sz is
// updated to the number of bytes written.
//
// Pass buf as nil and *sz as 0 to perform a size probe.
//
// Returns the number of bytes written (positive) on success, negative error
// code on failure.
// Requires wolfSSL built with WOLFSSL_DTLS and WOLFSSL_SESSION_EXPORT.
func WolfSSL_dtls_export_state_only(ssl *WOLFSSL, buf []byte, sz *int) int {
	if sz == nil {
		return BAD_FUNC_ARG
	}
	var bufPtr *C.uchar
	if len(buf) > 0 {
		bufPtr = (*C.uchar)(unsafe.Pointer(&buf[0]))
	}
	cSz := C.uint(*sz)
	ret := int(C.go_wolfSSL_dtls_export_state_only((*C.struct_WOLFSSL)(ssl), bufPtr, &cSz))
	*sz = int(cSz)
	return ret
}

// WolfSSL_dtls_import restores a DTLS session from the serialised state in
// buf. sz must equal the number of valid bytes in buf.
//
// Returns the number of bytes consumed (positive) on success, negative error
// code on failure.
// Requires wolfSSL built with WOLFSSL_DTLS and WOLFSSL_SESSION_EXPORT.
func WolfSSL_dtls_import(ssl *WOLFSSL, buf []byte, sz int) int {
	if sz < 0 || sz > len(buf) {
		return BAD_FUNC_ARG
	}
	if len(buf) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wolfSSL_dtls_import(
		(*C.struct_WOLFSSL)(ssl),
		(*C.uchar)(unsafe.Pointer(&buf[0])),
		C.uint(sz)))
}

// WolfSSL_CTX_dtls_set_export registers a context-level DTLS session-export
// callback. fn must be a C function pointer of type wc_dtls_export cast to
// unsafe.Pointer, or nil to clear the callback.
//
// Returns WOLFSSL_SUCCESS (1) on success, negative on failure.
// Requires wolfSSL built with WOLFSSL_DTLS and WOLFSSL_SESSION_EXPORT.
func WolfSSL_CTX_dtls_set_export(ctx *WOLFSSL_CTX, fn unsafe.Pointer) int {
	return int(C.go_wolfSSL_CTX_dtls_set_export(
		(*C.struct_WOLFSSL_CTX)(ctx), fn))
}

// WolfSSL_dtls_get_peer copies the DTLS peer address stored in ssl into the
// peer buffer. On entry *peerSz must hold the buffer capacity; on success it
// is updated to the actual address size written.
//
// Returns WOLFSSL_SUCCESS (1) on success, negative on failure.
// Requires wolfSSL built with WOLFSSL_DTLS.
func WolfSSL_dtls_get_peer(ssl *WOLFSSL, peer []byte, peerSz *int) int {
	if peerSz == nil {
		return BAD_FUNC_ARG
	}
	if len(peer) == 0 {
		return BAD_FUNC_ARG
	}
	cSz := C.uint(*peerSz)
	ret := int(C.go_wolfSSL_dtls_get_peer(
		(*C.struct_WOLFSSL)(ssl),
		unsafe.Pointer(&peer[0]),
		&cSz))
	*peerSz = int(cSz)
	return ret
}

// WolfSSL_CTX_dtls_set_sctp enables SCTP mode for all sessions created from
// ctx. SCTP mode disables the DTLS record-layer fragmentation and uses SCTP's
// native partial-reliability instead.
//
// Returns WOLFSSL_SUCCESS (1) on success, negative on failure.
// Requires wolfSSL built with WOLFSSL_DTLS and WOLFSSL_SCTP.
func WolfSSL_CTX_dtls_set_sctp(ctx *WOLFSSL_CTX) int {
	return int(C.go_wolfSSL_CTX_dtls_set_sctp((*C.struct_WOLFSSL_CTX)(ctx)))
}

// WolfSSL_dtls_get_current_timeout returns the current DTLS retransmission
// timeout value in seconds for ssl. The timeout doubles on each retransmit
// (RFC 6347 §4.2.4 exponential back-off) up to the maximum set by
// WolfSSL_dtls_set_timeout_max.
//
// Returns the timeout in seconds (non-negative), or NOT_COMPILED_IN if wolfSSL
// was built without WOLFSSL_DTLS.
func WolfSSL_dtls_get_current_timeout(ssl *WOLFSSL) int {
	return int(C.go_wolfSSL_dtls_get_current_timeout((*C.struct_WOLFSSL)(ssl)))
}

// WolfSSL_dtls_set_timeout_init sets the initial DTLS retransmission timeout
// for ssl to timeout seconds. This is the starting value of the RFC 6347
// §4.2.4 exponential back-off timer; it must not exceed the maximum set by
// WolfSSL_dtls_set_timeout_max.
//
// Returns WOLFSSL_SUCCESS (1) on success, BAD_FUNC_ARG on invalid input, or
// NOT_COMPILED_IN if wolfSSL was built without WOLFSSL_DTLS.
func WolfSSL_dtls_set_timeout_init(ssl *WOLFSSL, timeout int) int {
	return int(C.go_wolfSSL_dtls_set_timeout_init(
		(*C.struct_WOLFSSL)(ssl), C.int(timeout)))
}

// WolfSSL_dtls_set_timeout_max sets the maximum DTLS retransmission timeout
// for ssl to timeout seconds. The RFC 6347 §4.2.4 back-off timer will not
// exceed this ceiling; it must be at least the init timeout.
//
// Returns WOLFSSL_SUCCESS (1) on success, BAD_FUNC_ARG on invalid input, or
// NOT_COMPILED_IN if wolfSSL was built without WOLFSSL_DTLS.
func WolfSSL_dtls_set_timeout_max(ssl *WOLFSSL, timeout int) int {
	return int(C.go_wolfSSL_dtls_set_timeout_max(
		(*C.struct_WOLFSSL)(ssl), C.int(timeout)))
}

// WolfSSL_dtls_got_timeout notifies ssl that the retransmission timer has
// fired. wolfSSL doubles the current timeout (RFC 6347 §4.2.4) and
// retransmits any pending flight of handshake messages.
//
// Returns WOLFSSL_SUCCESS (1) on success, WOLFSSL_FATAL_ERROR on error, or
// NOT_COMPILED_IN if wolfSSL was built without WOLFSSL_DTLS.
func WolfSSL_dtls_got_timeout(ssl *WOLFSSL) int {
	return int(C.go_wolfSSL_dtls_got_timeout((*C.struct_WOLFSSL)(ssl)))
}

// WolfSSL_dtls_retransmit retransmits the current handshake flight for ssl
// without advancing the RFC 6347 §4.2.4 back-off timer. Use this when the
// application has its own timer logic and only wants to trigger a send.
//
// Returns WOLFSSL_SUCCESS (1) on success, WOLFSSL_FATAL_ERROR on error, or
// NOT_COMPILED_IN if wolfSSL was built without WOLFSSL_DTLS.
func WolfSSL_dtls_retransmit(ssl *WOLFSSL) int {
	return int(C.go_wolfSSL_dtls_retransmit((*C.struct_WOLFSSL)(ssl)))
}

// WolfSSL_DTLS_SetCookieSecret sets the server-side DTLS cookie secret used
// in the RFC 6347 §4.2.1 stateless cookie exchange. Passing a nil secret
// causes wolfSSL to generate a random secret internally. secretSz must match
// the length of secret (or be 0 when secret is nil).
//
// Returns 0 on success, negative error code on failure, or NOT_COMPILED_IN if
// wolfSSL was built without WOLFSSL_DTLS or with NO_WOLFSSL_SERVER.
func WolfSSL_DTLS_SetCookieSecret(ssl *WOLFSSL, secret []byte, secretSz int) int {
	if secretSz < 0 || secretSz > len(secret) {
		return BAD_FUNC_ARG
	}
	var secretPtr *C.uchar
	if len(secret) > 0 {
		secretPtr = (*C.uchar)(unsafe.Pointer(&secret[0]))
	}
	return int(C.go_wolfSSL_DTLS_SetCookieSecret(
		(*C.struct_WOLFSSL)(ssl), secretPtr, C.uint(secretSz)))
}

// WolfDTLS_accept_stateless performs a single round of the RFC 6347 §4.2.1
// stateless cookie exchange on ssl. The server sends a HelloVerifyRequest,
// receives the retransmitted ClientHello with the cookie, and validates it —
// all without allocating per-client state. Call wolfSSL_accept after this
// function returns WOLFSSL_SUCCESS to complete the full handshake.
//
// Returns WOLFSSL_SUCCESS (1) when a valid-cookie ClientHello is received,
// WOLFSSL_FAILURE when WANT_READ or a cookie request was sent and a reply is
// still pending (call again when I/O is ready), WOLFSSL_FATAL_ERROR on a
// fatal error, or NOT_COMPILED_IN if wolfSSL was built without WOLFSSL_DTLS
// or with NO_WOLFSSL_SERVER.
func WolfDTLS_accept_stateless(ssl *WOLFSSL) int {
	return int(C.go_wolfDTLS_accept_stateless((*C.struct_WOLFSSL)(ssl)))
}
