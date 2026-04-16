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
import "C"
import (
	"unsafe"
)

// WolfSSL_dtls_export serialises the full DTLS session state of ssl into buf.
// On entry *sz must hold the capacity of buf in bytes; on success *sz is
// updated to the number of bytes written.
//
// Pass buf as nil and *sz as 0 to perform a size probe: wolfSSL returns the
// required buffer size in *sz and a negative error code (LENGTH_ONLY_E).
//
// Returns 0 on success, negative error code on failure.
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

// WolfSSL_dtls_import restores a DTLS session from the serialised state in
// buf. sz must equal the number of valid bytes in buf.
//
// Returns 0 on success, negative error code on failure.
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
