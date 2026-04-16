/* des3.go
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

// Package wolfSSL provides Go bindings for the wolfSSL C library.
//
// 3DES (Triple-DES) is NIST-deprecated and disallowed for new use after 2023
// (NIST SP 800-131A Rev. 2). It is provided only for legacy interoperability.
package wolfSSL

// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/des3.h>
// #ifdef NO_DES3
// #define DES_KEY_SIZE  1
// #define DES3_KEY_SIZE 1
// #define DES_IV_SIZE   1
// #define DES_BLOCK_SIZE 1
// #define DES_ENCRYPTION 0
// #define DES_DECRYPTION 1
// typedef struct Des3 {} Des3;
// int wc_Des3Init(Des3* des3, void* heap, int devId) {
//     return -174;
// }
// void wc_Des3Free(Des3* des3) {
//     return;
// }
// int wc_Des3_SetKey(Des3* des, const byte* key, const byte* iv, int dir) {
//     return -174;
// }
// int wc_Des3_SetIV(Des3* des, const byte* iv) {
//     return -174;
// }
// int wc_Des3_CbcEncrypt(Des3* des, byte* out, const byte* in, word32 sz) {
//     return -174;
// }
// int wc_Des3_CbcDecrypt(Des3* des, byte* out, const byte* in, word32 sz) {
//     return -174;
// }
// int wc_Des3_EcbEncrypt(Des3* des, byte* out, const byte* in, word32 sz) {
//     return -174;
// }
// #endif
import "C"
import "unsafe"

const DES_KEY_SIZE = int(C.DES_KEY_SIZE)
const DES3_KEY_SIZE = int(C.DES3_KEY_SIZE)
const DES_IV_SIZE = int(C.DES_IV_SIZE)
const DES_BLOCK_SIZE = int(C.DES_BLOCK_SIZE)
const DES_ENCRYPTION = int(C.DES_ENCRYPTION)
const DES_DECRYPTION = int(C.DES_DECRYPTION)

type Des3 = C.Des3

// Wc_Des3Init initialises a Des3 context.
// Security warning: 3DES is NIST-deprecated; use only for legacy interoperability.
func Wc_Des3Init(des3 *C.Des3, devId int) int {
	return int(C.wc_Des3Init(des3, unsafe.Pointer(nil), C.int(devId)))
}

// Wc_Des3Free releases resources held by a Des3 context.
// Security warning: 3DES is NIST-deprecated; use only for legacy interoperability.
func Wc_Des3Free(des3 *C.Des3) {
	C.wc_Des3Free(des3)
}

// Wc_Des3_SetKey sets the key and IV on des3. key must be DES3_KEY_SIZE bytes; iv must be DES_IV_SIZE bytes.
// Security warning: 3DES is NIST-deprecated; use only for legacy interoperability.
func Wc_Des3_SetKey(des3 *C.Des3, key []byte, iv []byte, dir int) int {
	if len(key) < DES3_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	if len(iv) < DES_IV_SIZE {
		return BAD_FUNC_ARG
	}
	return int(C.wc_Des3_SetKey(des3,
		(*C.uchar)(unsafe.Pointer(&key[0])),
		(*C.uchar)(unsafe.Pointer(&iv[0])),
		C.int(dir)))
}

// Wc_Des3_SetIV sets only the IV on des3. iv must be DES_IV_SIZE bytes.
// Security warning: 3DES is NIST-deprecated; use only for legacy interoperability.
func Wc_Des3_SetIV(des3 *C.Des3, iv []byte) int {
	if len(iv) < DES_IV_SIZE {
		return BAD_FUNC_ARG
	}
	return int(C.wc_Des3_SetIV(des3, (*C.uchar)(unsafe.Pointer(&iv[0]))))
}

// Wc_Des3_CbcEncrypt encrypts sz bytes from in into out using CBC mode.
// Security warning: 3DES is NIST-deprecated; use only for legacy interoperability.
func Wc_Des3_CbcEncrypt(des3 *C.Des3, out []byte, in []byte, sz int) int {
	if sz < 0 || sz > len(in) {
		return BAD_FUNC_ARG
	}
	if len(out) < sz {
		return BAD_FUNC_ARG
	}
	if sz == 0 {
		return 0
	}
	return int(C.wc_Des3_CbcEncrypt(des3,
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&in[0])),
		C.word32(sz)))
}

// Wc_Des3_CbcDecrypt decrypts sz bytes from in into out using CBC mode.
// Security warning: 3DES is NIST-deprecated; use only for legacy interoperability.
func Wc_Des3_CbcDecrypt(des3 *C.Des3, out []byte, in []byte, sz int) int {
	if sz < 0 || sz > len(in) {
		return BAD_FUNC_ARG
	}
	if len(out) < sz {
		return BAD_FUNC_ARG
	}
	if sz == 0 {
		return 0
	}
	return int(C.wc_Des3_CbcDecrypt(des3,
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&in[0])),
		C.word32(sz)))
}

// Wc_Des3_EcbEncrypt encrypts sz bytes from in into out using ECB mode.
// Security warning: 3DES is NIST-deprecated; use only for legacy interoperability.
func Wc_Des3_EcbEncrypt(des3 *C.Des3, out []byte, in []byte, sz int) int {
	if sz < 0 || sz > len(in) {
		return BAD_FUNC_ARG
	}
	if len(out) < sz {
		return BAD_FUNC_ARG
	}
	if sz == 0 {
		return 0
	}
	return int(C.wc_Des3_EcbEncrypt(des3,
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&in[0])),
		C.word32(sz)))
}
