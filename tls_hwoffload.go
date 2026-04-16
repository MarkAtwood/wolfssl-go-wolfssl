/* tls_hwoffload.go
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
// /* Callback typedefs used as function pointer parameters below.
//    Under HAVE_ECC and HAVE_PK_CALLBACKS wolfSSL defines CallbackEccSign,
//    CallbackEccVerify, and CallbackEccSharedSecret in ssl.h.  Under
//    HAVE_PK_CALLBACKS without HAVE_ECC the ECC callbacks are absent.
//    Similarly for NO_RSA.
//
//    We define stub types and shims so the Go side always compiles. */
//
// #ifndef HAVE_PK_CALLBACKS
// /* Stub types — never used at runtime when HAVE_PK_CALLBACKS is absent. */
// typedef int (*go_ecc_sign_cb)(void);
// typedef int (*go_ecc_verify_cb)(void);
// typedef int (*go_ecc_shared_cb)(void);
// typedef int (*go_rsa_sign_cb)(void);
// typedef int (*go_rsa_verify_cb)(void);
// typedef int (*go_rsa_enc_cb)(void);
// typedef int (*go_rsa_dec_cb)(void);
//
// static void go_wolfSSL_CTX_SetEccSignCb(WOLFSSL_CTX* ctx,
//         go_ecc_sign_cb cb) { (void)ctx; (void)cb; }
// static void go_wolfSSL_CTX_SetEccVerifyCb(WOLFSSL_CTX* ctx,
//         go_ecc_verify_cb cb) { (void)ctx; (void)cb; }
// static void go_wolfSSL_CTX_SetEccSharedSecretCb(WOLFSSL_CTX* ctx,
//         go_ecc_shared_cb cb) { (void)ctx; (void)cb; }
// static void go_wolfSSL_CTX_SetRsaSignCb(WOLFSSL_CTX* ctx,
//         go_rsa_sign_cb cb) { (void)ctx; (void)cb; }
// static void go_wolfSSL_CTX_SetRsaVerifyCb(WOLFSSL_CTX* ctx,
//         go_rsa_verify_cb cb) { (void)ctx; (void)cb; }
// static void go_wolfSSL_CTX_SetRsaEncCb(WOLFSSL_CTX* ctx,
//         go_rsa_enc_cb cb) { (void)ctx; (void)cb; }
// static void go_wolfSSL_CTX_SetRsaDecCb(WOLFSSL_CTX* ctx,
//         go_rsa_dec_cb cb) { (void)ctx; (void)cb; }
//
// #else /* HAVE_PK_CALLBACKS */
//
// /* ECC callbacks */
// #ifdef HAVE_ECC
// typedef CallbackEccSign    go_ecc_sign_cb;
// typedef CallbackEccVerify  go_ecc_verify_cb;
// typedef CallbackEccSharedSecret go_ecc_shared_cb;
// #else
// typedef int (*go_ecc_sign_cb)(void);
// typedef int (*go_ecc_verify_cb)(void);
// typedef int (*go_ecc_shared_cb)(void);
// #endif
//
// /* RSA callbacks */
// #ifndef NO_RSA
// typedef CallbackRsaSign   go_rsa_sign_cb;
// typedef CallbackRsaVerify go_rsa_verify_cb;
// typedef CallbackRsaEnc    go_rsa_enc_cb;
// typedef CallbackRsaDec    go_rsa_dec_cb;
// #else
// typedef int (*go_rsa_sign_cb)(void);
// typedef int (*go_rsa_verify_cb)(void);
// typedef int (*go_rsa_enc_cb)(void);
// typedef int (*go_rsa_dec_cb)(void);
// #endif
//
// static void go_wolfSSL_CTX_SetEccSignCb(WOLFSSL_CTX* ctx,
//         go_ecc_sign_cb cb) {
// #ifdef HAVE_ECC
//     wolfSSL_CTX_SetEccSignCb(ctx, cb);
// #else
//     (void)ctx; (void)cb;
// #endif
// }
//
// static void go_wolfSSL_CTX_SetEccVerifyCb(WOLFSSL_CTX* ctx,
//         go_ecc_verify_cb cb) {
// #ifdef HAVE_ECC
//     wolfSSL_CTX_SetEccVerifyCb(ctx, cb);
// #else
//     (void)ctx; (void)cb;
// #endif
// }
//
// static void go_wolfSSL_CTX_SetEccSharedSecretCb(WOLFSSL_CTX* ctx,
//         go_ecc_shared_cb cb) {
// #ifdef HAVE_ECC
//     wolfSSL_CTX_SetEccSharedSecretCb(ctx, cb);
// #else
//     (void)ctx; (void)cb;
// #endif
// }
//
// static void go_wolfSSL_CTX_SetRsaSignCb(WOLFSSL_CTX* ctx,
//         go_rsa_sign_cb cb) {
// #ifndef NO_RSA
//     wolfSSL_CTX_SetRsaSignCb(ctx, cb);
// #else
//     (void)ctx; (void)cb;
// #endif
// }
//
// static void go_wolfSSL_CTX_SetRsaVerifyCb(WOLFSSL_CTX* ctx,
//         go_rsa_verify_cb cb) {
// #ifndef NO_RSA
//     wolfSSL_CTX_SetRsaVerifyCb(ctx, cb);
// #else
//     (void)ctx; (void)cb;
// #endif
// }
//
// static void go_wolfSSL_CTX_SetRsaEncCb(WOLFSSL_CTX* ctx,
//         go_rsa_enc_cb cb) {
// #ifndef NO_RSA
//     wolfSSL_CTX_SetRsaEncCb(ctx, cb);
// #else
//     (void)ctx; (void)cb;
// #endif
// }
//
// static void go_wolfSSL_CTX_SetRsaDecCb(WOLFSSL_CTX* ctx,
//         go_rsa_dec_cb cb) {
// #ifndef NO_RSA
//     wolfSSL_CTX_SetRsaDecCb(ctx, cb);
// #else
//     (void)ctx; (void)cb;
// #endif
// }
//
// #endif /* HAVE_PK_CALLBACKS */
import "C"
import (
	"unsafe"
)

// WolfSSL_CTX_SetEccSignCb registers a hardware-offload callback for ECC
// signing on all sessions derived from ctx.
//
// cb must be a C CallbackEccSign function pointer cast to unsafe.Pointer, or
// nil to clear the callback. Pass nil to fall back to wolfSSL's software
// implementation.
//
// Requires wolfSSL built with HAVE_PK_CALLBACKS and HAVE_ECC; a no-op
// otherwise.
func WolfSSL_CTX_SetEccSignCb(ctx *WOLFSSL_CTX, cb unsafe.Pointer) {
	C.go_wolfSSL_CTX_SetEccSignCb(
		(*C.struct_WOLFSSL_CTX)(ctx),
		(C.go_ecc_sign_cb)(cb))
}

// WolfSSL_CTX_SetEccVerifyCb registers a hardware-offload callback for ECC
// signature verification on all sessions derived from ctx.
//
// cb must be a C CallbackEccVerify function pointer cast to unsafe.Pointer, or
// nil to clear the callback.
//
// Requires wolfSSL built with HAVE_PK_CALLBACKS and HAVE_ECC; a no-op
// otherwise.
func WolfSSL_CTX_SetEccVerifyCb(ctx *WOLFSSL_CTX, cb unsafe.Pointer) {
	C.go_wolfSSL_CTX_SetEccVerifyCb(
		(*C.struct_WOLFSSL_CTX)(ctx),
		(C.go_ecc_verify_cb)(cb))
}

// WolfSSL_CTX_SetEccSharedSecretCb registers a hardware-offload callback for
// ECDH shared-secret computation (key agreement) on all sessions derived from
// ctx.
//
// cb must be a C CallbackEccSharedSecret function pointer cast to
// unsafe.Pointer, or nil to clear the callback.
//
// Requires wolfSSL built with HAVE_PK_CALLBACKS and HAVE_ECC; a no-op
// otherwise.
func WolfSSL_CTX_SetEccSharedSecretCb(ctx *WOLFSSL_CTX, cb unsafe.Pointer) {
	C.go_wolfSSL_CTX_SetEccSharedSecretCb(
		(*C.struct_WOLFSSL_CTX)(ctx),
		(C.go_ecc_shared_cb)(cb))
}

// WolfSSL_CTX_SetRsaSignCb registers a hardware-offload callback for RSA
// private-key signing on all sessions derived from ctx.
//
// cb must be a C CallbackRsaSign function pointer cast to unsafe.Pointer, or
// nil to clear the callback.
//
// Requires wolfSSL built with HAVE_PK_CALLBACKS; a no-op otherwise.
func WolfSSL_CTX_SetRsaSignCb(ctx *WOLFSSL_CTX, cb unsafe.Pointer) {
	C.go_wolfSSL_CTX_SetRsaSignCb(
		(*C.struct_WOLFSSL_CTX)(ctx),
		(C.go_rsa_sign_cb)(cb))
}

// WolfSSL_CTX_SetRsaVerifyCb registers a hardware-offload callback for RSA
// signature verification on all sessions derived from ctx.
//
// cb must be a C CallbackRsaVerify function pointer cast to unsafe.Pointer, or
// nil to clear the callback.
//
// Requires wolfSSL built with HAVE_PK_CALLBACKS; a no-op otherwise.
func WolfSSL_CTX_SetRsaVerifyCb(ctx *WOLFSSL_CTX, cb unsafe.Pointer) {
	C.go_wolfSSL_CTX_SetRsaVerifyCb(
		(*C.struct_WOLFSSL_CTX)(ctx),
		(C.go_rsa_verify_cb)(cb))
}

// WolfSSL_CTX_SetRsaEncCb registers a hardware-offload callback for RSA
// public-key encryption on all sessions derived from ctx.
//
// cb must be a C CallbackRsaEnc function pointer cast to unsafe.Pointer, or
// nil to clear the callback.
//
// Requires wolfSSL built with HAVE_PK_CALLBACKS; a no-op otherwise.
func WolfSSL_CTX_SetRsaEncCb(ctx *WOLFSSL_CTX, cb unsafe.Pointer) {
	C.go_wolfSSL_CTX_SetRsaEncCb(
		(*C.struct_WOLFSSL_CTX)(ctx),
		(C.go_rsa_enc_cb)(cb))
}

// WolfSSL_CTX_SetRsaDecCb registers a hardware-offload callback for RSA
// private-key decryption on all sessions derived from ctx.
//
// cb must be a C CallbackRsaDec function pointer cast to unsafe.Pointer, or
// nil to clear the callback.
//
// Requires wolfSSL built with HAVE_PK_CALLBACKS; a no-op otherwise.
func WolfSSL_CTX_SetRsaDecCb(ctx *WOLFSSL_CTX, cb unsafe.Pointer) {
	C.go_wolfSSL_CTX_SetRsaDecCb(
		(*C.struct_WOLFSSL_CTX)(ctx),
		(C.go_rsa_dec_cb)(cb))
}
