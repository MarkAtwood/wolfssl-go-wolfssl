/* ocsp.go
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
// #ifndef HAVE_OCSP
// int wolfSSL_CTX_EnableOCSP(WOLFSSL_CTX* ctx, int options) {
//     return -174;
// }
// int wolfSSL_CTX_DisableOCSP(WOLFSSL_CTX* ctx) {
//     return -174;
// }
// int wolfSSL_CTX_SetOCSP_OverrideURL(WOLFSSL_CTX* ctx, const char* url) {
//     return -174;
// }
// int wolfSSL_CTX_SetOCSP_Cb(WOLFSSL_CTX* ctx,
//                            CbOCSPIO ioCb, CbOCSPRespFree respFreeCb,
//                            void* ioCbCtx) {
//     return -174;
// }
// int wolfSSL_CTX_EnableOCSPStapling(WOLFSSL_CTX* ctx) {
//     return -174;
// }
// int wolfSSL_CTX_DisableOCSPStapling(WOLFSSL_CTX* ctx) {
//     return -174;
// }
// int wolfSSL_CTX_EnableOCSPMustStaple(WOLFSSL_CTX* ctx) {
//     return -174;
// }
// int wolfSSL_CTX_DisableOCSPMustStaple(WOLFSSL_CTX* ctx) {
//     return -174;
// }
// #endif /* !HAVE_OCSP */
import "C"
import "unsafe"

// WolfSSL_CTX_EnableOCSP enables OCSP certificate verification on the context.
// options is a bitmask of WOLFSSL_OCSP_* flags (e.g. WOLFSSL_OCSP_NO_NONCE).
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_CTX_EnableOCSP(ctx *C.struct_WOLFSSL_CTX, options int) int {
	return int(C.wolfSSL_CTX_EnableOCSP(ctx, C.int(options)))
}

// WolfSSL_CTX_DisableOCSP disables OCSP certificate verification on the context.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_CTX_DisableOCSP(ctx *C.struct_WOLFSSL_CTX) int {
	return int(C.wolfSSL_CTX_DisableOCSP(ctx))
}

// WolfSSL_CTX_SetOCSP_OverrideURL sets an override URL for OCSP requests,
// bypassing the URL embedded in certificates.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_CTX_SetOCSP_OverrideURL(ctx *C.struct_WOLFSSL_CTX, url string) int {
	c_url := C.CString(url)
	defer C.free(unsafe.Pointer(c_url))
	return int(C.wolfSSL_CTX_SetOCSP_OverrideURL(ctx, c_url))
}

// WolfSSL_CTX_SetOCSP_Cb sets custom I/O and response-free callbacks for OCSP.
// ioCb is a CbOCSPIO function pointer; respFreeCb is a CbOCSPRespFree function pointer;
// ioCbCtx is an opaque context pointer passed through to both callbacks.
// Pass nil for any callback to clear it.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_CTX_SetOCSP_Cb(ctx *C.struct_WOLFSSL_CTX, ioCb unsafe.Pointer,
	respFreeCb unsafe.Pointer, ioCbCtx unsafe.Pointer) int {
	return int(C.wolfSSL_CTX_SetOCSP_Cb(ctx,
		(C.CbOCSPIO)(ioCb),
		(C.CbOCSPRespFree)(respFreeCb),
		ioCbCtx))
}

// WolfSSL_CTX_EnableOCSPStapling enables OCSP stapling (must-staple) on the context.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_CTX_EnableOCSPStapling(ctx *C.struct_WOLFSSL_CTX) int {
	return int(C.wolfSSL_CTX_EnableOCSPStapling(ctx))
}

// WolfSSL_CTX_DisableOCSPStapling disables OCSP stapling on the context.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_CTX_DisableOCSPStapling(ctx *C.struct_WOLFSSL_CTX) int {
	return int(C.wolfSSL_CTX_DisableOCSPStapling(ctx))
}

// WolfSSL_CTX_EnableOCSPMustStaple requires peers to provide an OCSP staple.
// Connections from peers that do not staple will be rejected.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_CTX_EnableOCSPMustStaple(ctx *C.struct_WOLFSSL_CTX) int {
	return int(C.wolfSSL_CTX_EnableOCSPMustStaple(ctx))
}

// WolfSSL_CTX_DisableOCSPMustStaple removes the requirement for peers to staple.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_CTX_DisableOCSPMustStaple(ctx *C.struct_WOLFSSL_CTX) int {
	return int(C.wolfSSL_CTX_DisableOCSPMustStaple(ctx))
}
