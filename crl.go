/* crl.go
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

// #include <wolfssl/options.h>
// #include <wolfssl/ssl.h>
// #ifndef HAVE_CRL
// static int wolfSSL_CTX_EnableCRL(WOLFSSL_CTX* ctx, int options)
//     { (void)ctx; (void)options; return -174; }
// static int wolfSSL_CTX_DisableCRL(WOLFSSL_CTX* ctx)
//     { (void)ctx; return -174; }
// static int wolfSSL_CTX_LoadCRL(WOLFSSL_CTX* ctx, const char* path, int type, int monitor)
//     { (void)ctx; (void)path; (void)type; (void)monitor; return -174; }
// static int wolfSSL_CTX_LoadCRLBuffer(WOLFSSL_CTX* ctx, const unsigned char* buff,
//                                       long sz, int type)
//     { (void)ctx; (void)buff; (void)sz; (void)type; return -174; }
// typedef void (*CbMissingCRL)(const char* url);
// static int wolfSSL_CTX_SetCRL_Cb(WOLFSSL_CTX* ctx, CbMissingCRL cb)
//     { (void)ctx; (void)cb; return -174; }
// #endif
import "C"
import "unsafe"

// WolfSSL_CTX_EnableCRL enables CRL checking on ctx. options may be 0 or
// WOLFSSL_CRL_CHECKALL. Requires HAVE_CRL at build time.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_CTX_EnableCRL(ctx *WOLFSSL_CTX, options int) int {
	return int(C.wolfSSL_CTX_EnableCRL(ctx, C.int(options)))
}

// WolfSSL_CTX_DisableCRL disables CRL checking on ctx.
// Requires HAVE_CRL at build time.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_CTX_DisableCRL(ctx *WOLFSSL_CTX) int {
	return int(C.wolfSSL_CTX_DisableCRL(ctx))
}

// WolfSSL_CTX_LoadCRL loads CRL data from the directory path into ctx.
// crlType is SSL_FILETYPE_PEM or SSL_FILETYPE_ASN1. monitor enables directory
// monitoring when non-zero. Requires HAVE_CRL at build time.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_CTX_LoadCRL(ctx *WOLFSSL_CTX, path string, crlType int, monitor int) int {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	return int(C.wolfSSL_CTX_LoadCRL(ctx, cPath, C.int(crlType), C.int(monitor)))
}

// WolfSSL_CTX_LoadCRLBuffer loads a PEM or DER CRL from buf into ctx.
// crlType is SSL_FILETYPE_PEM or SSL_FILETYPE_ASN1.
// Requires HAVE_CRL at build time.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_CTX_LoadCRLBuffer(ctx *WOLFSSL_CTX, buf []byte, sz int, crlType int) int {
	if sz < 0 || sz > len(buf) || len(buf) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.wolfSSL_CTX_LoadCRLBuffer(ctx,
		(*C.uchar)(unsafe.Pointer(&buf[0])), C.long(sz), C.int(crlType)))
}

// WolfSSL_CTX_SetCRL_Cb sets a callback invoked when a CRL is missing for a
// certificate being verified. cb must be a C function pointer of type
// void (*)(const char* url), passed as unsafe.Pointer.
// Requires HAVE_CRL at build time.
// Returns WOLFSSL_SUCCESS on success, negative on error.
func WolfSSL_CTX_SetCRL_Cb(ctx *WOLFSSL_CTX, cb unsafe.Pointer) int {
	return int(C.wolfSSL_CTX_SetCRL_Cb(ctx, (*[0]byte)(cb)))
}
