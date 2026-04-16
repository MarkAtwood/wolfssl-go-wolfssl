/* tls_callbacks.go
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
// #include <wolfssl/wolfio.h>
import "C"
import (
	"unsafe"
)

// WolfSSL_CTX_set_verify sets the certificate verification mode and optional
// callback on a WOLFSSL_CTX.  mode is a bitmask of WOLFSSL_VERIFY_* constants.
// cb must be a C VerifyCallback function pointer cast to unsafe.Pointer, or
// nil to use the default behaviour.
func WolfSSL_CTX_set_verify(ctx *C.struct_WOLFSSL_CTX, mode int, cb unsafe.Pointer) {
	C.wolfSSL_CTX_set_verify(ctx, C.int(mode), (*[0]byte)(cb))
}

// WolfSSL_set_verify sets the certificate verification mode and optional
// callback on a single WOLFSSL session.  cb must be a C VerifyCallback
// function pointer cast to unsafe.Pointer, or nil.
func WolfSSL_set_verify(ssl *C.struct_WOLFSSL, mode int, cb unsafe.Pointer) {
	C.wolfSSL_set_verify(ssl, C.int(mode), (*[0]byte)(cb))
}

// WolfSSL_CTX_SetIORecv sets a custom I/O receive callback on a WOLFSSL_CTX.
// cb must be a C CallbackIORecv function pointer cast to unsafe.Pointer, or
// nil to restore the default network receive handler.
func WolfSSL_CTX_SetIORecv(ctx *C.struct_WOLFSSL_CTX, cb unsafe.Pointer) {
	C.wolfSSL_CTX_SetIORecv(ctx, (*[0]byte)(cb))
}

// WolfSSL_CTX_SetIOSend sets a custom I/O send callback on a WOLFSSL_CTX.
// cb must be a C CallbackIOSend function pointer cast to unsafe.Pointer, or
// nil to restore the default network send handler.
func WolfSSL_CTX_SetIOSend(ctx *C.struct_WOLFSSL_CTX, cb unsafe.Pointer) {
	C.wolfSSL_CTX_SetIOSend(ctx, (*[0]byte)(cb))
}

// WolfSSL_SSLSetIORecv sets a custom I/O receive callback on a single WOLFSSL
// session, overriding the context-level callback for that session.
func WolfSSL_SSLSetIORecv(ssl *C.struct_WOLFSSL, cb unsafe.Pointer) {
	C.wolfSSL_SSLSetIORecv(ssl, (*[0]byte)(cb))
}

// WolfSSL_SSLSetIOSend sets a custom I/O send callback on a single WOLFSSL
// session, overriding the context-level callback for that session.
func WolfSSL_SSLSetIOSend(ssl *C.struct_WOLFSSL, cb unsafe.Pointer) {
	C.wolfSSL_SSLSetIOSend(ssl, (*[0]byte)(cb))
}

// WolfSSL_SetIOReadCtx sets the user context pointer passed to the custom I/O
// receive callback for a WOLFSSL session.
func WolfSSL_SetIOReadCtx(ssl *C.struct_WOLFSSL, ctx unsafe.Pointer) {
	C.wolfSSL_SetIOReadCtx(ssl, ctx)
}

// WolfSSL_SetIOWriteCtx sets the user context pointer passed to the custom I/O
// send callback for a WOLFSSL session.
func WolfSSL_SetIOWriteCtx(ssl *C.struct_WOLFSSL, ctx unsafe.Pointer) {
	C.wolfSSL_SetIOWriteCtx(ssl, ctx)
}
