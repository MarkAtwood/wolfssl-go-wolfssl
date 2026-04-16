/* aes_eax.go
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

// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/aes.h>
// #ifndef WOLFSSL_AES_EAX
// typedef struct AesEax {} AesEax;
// #endif
// #ifdef WOLFSSL_AES_EAX
// static int wc_AesEaxInit_shim(AesEax* eax,
//     const byte* key, word32 keySz,
//     const byte* nonce, word32 nonceSz,
//     const byte* authIn, word32 authInSz) {
//     return wc_AesEaxInit(eax, key, keySz, nonce, nonceSz, authIn, authInSz);
// }
// static int wc_AesEaxEncryptUpdate_shim(AesEax* eax, byte* out,
//     const byte* in, word32 inSz,
//     const byte* authIn, word32 authInSz) {
//     return wc_AesEaxEncryptUpdate(eax, out, in, inSz, authIn, authInSz);
// }
// static int wc_AesEaxDecryptUpdate_shim(AesEax* eax, byte* out,
//     const byte* in, word32 inSz,
//     const byte* authIn, word32 authInSz) {
//     return wc_AesEaxDecryptUpdate(eax, out, in, inSz, authIn, authInSz);
// }
// static int wc_AesEaxAuthDataUpdate_shim(AesEax* eax,
//     const byte* authIn, word32 authInSz) {
//     return wc_AesEaxAuthDataUpdate(eax, authIn, authInSz);
// }
// static int wc_AesEaxEncryptFinal_shim(AesEax* eax,
//     byte* authTag, word32 authTagSz) {
//     return wc_AesEaxEncryptFinal(eax, authTag, authTagSz);
// }
// static int wc_AesEaxDecryptFinal_shim(AesEax* eax,
//     const byte* authTag, word32 authTagSz) {
//     return wc_AesEaxDecryptFinal(eax, authTag, authTagSz);
// }
// static int wc_AesEaxFree_shim(AesEax* eax) {
//     return wc_AesEaxFree(eax);
// }
// #else
// static int wc_AesEaxInit_shim(AesEax* eax,
//     const byte* key, word32 keySz,
//     const byte* nonce, word32 nonceSz,
//     const byte* authIn, word32 authInSz) {
//     (void)eax; (void)key; (void)keySz; (void)nonce; (void)nonceSz;
//     (void)authIn; (void)authInSz;
//     return -174;
// }
// static int wc_AesEaxEncryptUpdate_shim(AesEax* eax, byte* out,
//     const byte* in, word32 inSz,
//     const byte* authIn, word32 authInSz) {
//     (void)eax; (void)out; (void)in; (void)inSz;
//     (void)authIn; (void)authInSz;
//     return -174;
// }
// static int wc_AesEaxDecryptUpdate_shim(AesEax* eax, byte* out,
//     const byte* in, word32 inSz,
//     const byte* authIn, word32 authInSz) {
//     (void)eax; (void)out; (void)in; (void)inSz;
//     (void)authIn; (void)authInSz;
//     return -174;
// }
// static int wc_AesEaxAuthDataUpdate_shim(AesEax* eax,
//     const byte* authIn, word32 authInSz) {
//     (void)eax; (void)authIn; (void)authInSz;
//     return -174;
// }
// static int wc_AesEaxEncryptFinal_shim(AesEax* eax,
//     byte* authTag, word32 authTagSz) {
//     (void)eax; (void)authTag; (void)authTagSz;
//     return -174;
// }
// static int wc_AesEaxDecryptFinal_shim(AesEax* eax,
//     const byte* authTag, word32 authTagSz) {
//     (void)eax; (void)authTag; (void)authTagSz;
//     return -174;
// }
// static int wc_AesEaxFree_shim(AesEax* eax) {
//     (void)eax;
//     return -174;
// }
// #endif
import "C"
import (
	"unsafe"
)

// AES_EAX_AUTH_E is returned by Wc_AesEaxDecryptFinal when the authentication
// tag does not match (wolfSSL error code -122).
const AES_EAX_AUTH_E = -122

// AesEax is the streaming AEAD state for AES-EAX.
// Lifecycle: Wc_AesEaxInit → (Wc_AesEaxEncryptUpdate or Wc_AesEaxDecryptUpdate
// or Wc_AesEaxAuthDataUpdate)* → Wc_AesEaxEncryptFinal or Wc_AesEaxDecryptFinal
// → Wc_AesEaxFree.
// NOT thread-safe.
type AesEax = C.struct_AesEax

// Wc_AesEaxInit initialises the AES-EAX context. key must be 16, 24, or 32
// bytes; keySz must be <= len(key). nonce is the per-message nonce; nonceSz
// must be <= len(nonce). authIn is optional additional authenticated data for
// the Init step (pass nil and authInSz=0 if none); authInSz must be
// <= len(authIn). Returns 0 on success.
func Wc_AesEaxInit(eax *AesEax,
	key []byte, keySz int,
	nonce []byte, nonceSz int,
	authIn []byte, authInSz int) int {
	if keySz < 0 || keySz > len(key) {
		return BAD_FUNC_ARG
	}
	if nonceSz < 0 || nonceSz > len(nonce) {
		return BAD_FUNC_ARG
	}
	if authInSz < 0 || authInSz > len(authIn) {
		return BAD_FUNC_ARG
	}
	if keySz == 0 || nonceSz == 0 {
		return BAD_FUNC_ARG
	}
	var sanAuthIn *C.uchar
	if authInSz > 0 {
		sanAuthIn = (*C.uchar)(unsafe.Pointer(&authIn[0]))
	}
	return int(C.wc_AesEaxInit_shim(eax,
		(*C.uchar)(unsafe.Pointer(&key[0])), C.word32(keySz),
		(*C.uchar)(unsafe.Pointer(&nonce[0])), C.word32(nonceSz),
		sanAuthIn, C.word32(authInSz)))
}

// Wc_AesEaxEncryptUpdate encrypts inSz bytes from in into out, and optionally
// feeds authInSz bytes of additional authenticated data. inSz must be
// <= len(in); out must be at least inSz bytes. authInSz must be <= len(authIn);
// pass nil/0 if there is no additional data for this call. Returns 0 on
// success.
func Wc_AesEaxEncryptUpdate(eax *AesEax,
	out []byte,
	in []byte, inSz int,
	authIn []byte, authInSz int) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	if len(out) < inSz {
		return BAD_FUNC_ARG
	}
	if authInSz < 0 || authInSz > len(authIn) {
		return BAD_FUNC_ARG
	}
	var sanOut *C.uchar
	if inSz > 0 {
		sanOut = (*C.uchar)(unsafe.Pointer(&out[0]))
	}
	var sanIn *C.uchar
	if inSz > 0 {
		sanIn = (*C.uchar)(unsafe.Pointer(&in[0]))
	}
	var sanAuthIn *C.uchar
	if authInSz > 0 {
		sanAuthIn = (*C.uchar)(unsafe.Pointer(&authIn[0]))
	}
	return int(C.wc_AesEaxEncryptUpdate_shim(eax,
		sanOut, sanIn, C.word32(inSz),
		sanAuthIn, C.word32(authInSz)))
}

// Wc_AesEaxDecryptUpdate decrypts inSz bytes from in into out, and optionally
// feeds authInSz bytes of additional authenticated data. inSz must be
// <= len(in); out must be at least inSz bytes. authInSz must be <= len(authIn);
// pass nil/0 if there is no additional data for this call. Returns 0 on
// success.
func Wc_AesEaxDecryptUpdate(eax *AesEax,
	out []byte,
	in []byte, inSz int,
	authIn []byte, authInSz int) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	if len(out) < inSz {
		return BAD_FUNC_ARG
	}
	if authInSz < 0 || authInSz > len(authIn) {
		return BAD_FUNC_ARG
	}
	var sanOut *C.uchar
	if inSz > 0 {
		sanOut = (*C.uchar)(unsafe.Pointer(&out[0]))
	}
	var sanIn *C.uchar
	if inSz > 0 {
		sanIn = (*C.uchar)(unsafe.Pointer(&in[0]))
	}
	var sanAuthIn *C.uchar
	if authInSz > 0 {
		sanAuthIn = (*C.uchar)(unsafe.Pointer(&authIn[0]))
	}
	return int(C.wc_AesEaxDecryptUpdate_shim(eax,
		sanOut, sanIn, C.word32(inSz),
		sanAuthIn, C.word32(authInSz)))
}

// Wc_AesEaxAuthDataUpdate feeds authInSz bytes of additional authenticated
// data without producing any output. authInSz must be <= len(authIn).
// Returns 0 on success.
func Wc_AesEaxAuthDataUpdate(eax *AesEax, authIn []byte, authInSz int) int {
	if authInSz < 0 || authInSz > len(authIn) {
		return BAD_FUNC_ARG
	}
	var sanAuthIn *C.uchar
	if authInSz > 0 {
		sanAuthIn = (*C.uchar)(unsafe.Pointer(&authIn[0]))
	}
	return int(C.wc_AesEaxAuthDataUpdate_shim(eax, sanAuthIn, C.word32(authInSz)))
}

// Wc_AesEaxEncryptFinal finalises encryption and writes the authentication tag
// into authTag. authTagSz must be in [1, AES_BLOCK_SIZE] and <= len(authTag).
// Returns 0 on success. Call Wc_AesEaxFree after this.
func Wc_AesEaxEncryptFinal(eax *AesEax, authTag []byte, authTagSz int) int {
	if authTagSz < 1 || authTagSz > AES_BLOCK_SIZE {
		return BAD_FUNC_ARG
	}
	if authTagSz > len(authTag) {
		return BAD_FUNC_ARG
	}
	return int(C.wc_AesEaxEncryptFinal_shim(eax,
		(*C.uchar)(unsafe.Pointer(&authTag[0])), C.word32(authTagSz)))
}

// Wc_AesEaxDecryptFinal verifies the authentication tag in authTag against the
// data processed so far. authTagSz must be in [1, AES_BLOCK_SIZE] and
// <= len(authTag). Returns 0 on success, AES_EAX_AUTH_E (-122) on tag
// mismatch. Call Wc_AesEaxFree after this regardless of the return value.
func Wc_AesEaxDecryptFinal(eax *AesEax, authTag []byte, authTagSz int) int {
	if authTagSz < 1 || authTagSz > AES_BLOCK_SIZE {
		return BAD_FUNC_ARG
	}
	if authTagSz > len(authTag) {
		return BAD_FUNC_ARG
	}
	return int(C.wc_AesEaxDecryptFinal_shim(eax,
		(*C.uchar)(unsafe.Pointer(&authTag[0])), C.word32(authTagSz)))
}

// Wc_AesEaxFree releases resources held by the AES-EAX context. Must be
// called after Wc_AesEaxEncryptFinal or Wc_AesEaxDecryptFinal (or on any
// error path after a successful Wc_AesEaxInit). Returns 0 on success.
func Wc_AesEaxFree(eax *AesEax) int {
	return int(C.wc_AesEaxFree_shim(eax))
}
