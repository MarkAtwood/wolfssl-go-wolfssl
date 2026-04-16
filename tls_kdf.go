/* tls_kdf.go
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
// #include <wolfssl/wolfcrypt/kdf.h>
// #ifndef WOLFSSL_HAVE_PRF
// static int wc_PRF(byte* result, word32 resLen, const byte* secret,
//     word32 secLen, const byte* seed, word32 seedLen, int hash,
//     void* heap, int devId) {
//     (void)result; (void)resLen; (void)secret; (void)secLen;
//     (void)seed; (void)seedLen; (void)hash; (void)heap; (void)devId;
//     return -174;
// }
// static int wc_PRF_TLS(byte* digest, word32 digLen, const byte* secret,
//     word32 secLen, const byte* label, word32 labLen,
//     const byte* seed, word32 seedLen, int useAtLeastSha256,
//     int hash_type, void* heap, int devId) {
//     (void)digest; (void)digLen; (void)secret; (void)secLen;
//     (void)label; (void)labLen; (void)seed; (void)seedLen;
//     (void)useAtLeastSha256; (void)hash_type; (void)heap; (void)devId;
//     return -174;
// }
// #endif
// #ifndef HAVE_KEYING_MATERIAL
// static int wolfSSL_export_keying_material(WOLFSSL *ssl,
//     unsigned char *out, size_t outLen,
//     const char *label, size_t labelLen,
//     const unsigned char *context, size_t contextLen,
//     int use_context) {
//     (void)ssl; (void)out; (void)outLen; (void)label; (void)labelLen;
//     (void)context; (void)contextLen; (void)use_context;
//     return -174;
// }
// #endif
import "C"
import "unsafe"

// Wc_PRF computes the TLS PRF (pseudo-random function) over a secret and seed
// using the specified hash algorithm (e.g., WC_SHA256).
// result receives the derived bytes; returns 0 on success, negative on error.
// Returns -174 if WOLFSSL_HAVE_PRF was not compiled in (requires !NO_KDF && !NO_HMAC).
func Wc_PRF(result []byte, secret []byte, seed []byte, hash int) int {
	if len(result) == 0 {
		return -1
	}
	var secretPtr *C.byte
	if len(secret) > 0 {
		secretPtr = (*C.byte)(unsafe.Pointer(&secret[0]))
	}
	var seedPtr *C.byte
	if len(seed) > 0 {
		seedPtr = (*C.byte)(unsafe.Pointer(&seed[0]))
	}
	return int(C.wc_PRF(
		(*C.byte)(unsafe.Pointer(&result[0])), C.word32(len(result)),
		secretPtr, C.word32(len(secret)),
		seedPtr, C.word32(len(seed)),
		C.int(hash),
		nil, 0,
	))
}

// Wc_PRF_TLS computes the TLS 1.2 PRF with a distinct label and seed, using
// the specified hash type. Set useAtLeastSha256 to 1 to enforce SHA-256 minimum.
// Returns 0 on success, negative on error.
// Returns -174 if WOLFSSL_HAVE_PRF was not compiled in.
func Wc_PRF_TLS(digest []byte, secret []byte, label []byte, seed []byte,
	useAtLeastSha256 int, hashType int) int {
	if len(digest) == 0 {
		return -1
	}
	var secretPtr *C.byte
	if len(secret) > 0 {
		secretPtr = (*C.byte)(unsafe.Pointer(&secret[0]))
	}
	var labelPtr *C.byte
	if len(label) > 0 {
		labelPtr = (*C.byte)(unsafe.Pointer(&label[0]))
	}
	var seedPtr *C.byte
	if len(seed) > 0 {
		seedPtr = (*C.byte)(unsafe.Pointer(&seed[0]))
	}
	return int(C.wc_PRF_TLS(
		(*C.byte)(unsafe.Pointer(&digest[0])), C.word32(len(digest)),
		secretPtr, C.word32(len(secret)),
		labelPtr, C.word32(len(label)),
		seedPtr, C.word32(len(seed)),
		C.int(useAtLeastSha256),
		C.int(hashType),
		nil, 0,
	))
}

// WolfSSL_export_keying_material exports keying material from a TLS session
// per RFC 5705. out receives outLen bytes derived from label and optional
// context. Set useContext to 1 to include context in the derivation.
// Returns WOLFSSL_SUCCESS (1) on success.
// Returns -174 if HAVE_KEYING_MATERIAL was not compiled in.
func WolfSSL_export_keying_material(ssl *C.struct_WOLFSSL, out []byte,
	label string, context []byte, useContext int) int {
	if len(out) == 0 {
		return -1
	}
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))

	var contextPtr *C.uchar
	contextLen := C.size_t(0)
	if len(context) > 0 {
		contextPtr = (*C.uchar)(unsafe.Pointer(&context[0]))
		contextLen = C.size_t(len(context))
	}

	return int(C.wolfSSL_export_keying_material(
		ssl,
		(*C.uchar)(unsafe.Pointer(&out[0])), C.size_t(len(out)),
		cLabel, C.size_t(len(label)),
		contextPtr, contextLen,
		C.int(useContext),
	))
}
