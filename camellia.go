/* camellia.go
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
// #include <wolfssl/wolfcrypt/camellia.h>
// #ifndef HAVE_CAMELLIA
// #define WC_CAMELLIA_BLOCK_SIZE 1
// typedef struct wc_Camellia {} wc_Camellia;
// int wc_CamelliaSetKey(wc_Camellia* cam, const byte* key, word32 len,
//                       const byte* iv) {
//     return -174;
// }
// int wc_CamelliaSetIV(wc_Camellia* cam, const byte* iv) {
//     return -174;
// }
// int wc_CamelliaEncryptDirect(wc_Camellia* cam, byte* out, const byte* in) {
//     return -174;
// }
// int wc_CamelliaDecryptDirect(wc_Camellia* cam, byte* out, const byte* in) {
//     return -174;
// }
// int wc_CamelliaCbcEncrypt(wc_Camellia* cam, byte* out, const byte* in,
//                            word32 sz) {
//     return -174;
// }
// int wc_CamelliaCbcDecrypt(wc_Camellia* cam, byte* out, const byte* in,
//                            word32 sz) {
//     return -174;
// }
// #endif
import "C"
import "unsafe"

const WC_CAMELLIA_BLOCK_SIZE = int(C.WC_CAMELLIA_BLOCK_SIZE)

type Wc_Camellia = C.struct_wc_Camellia

func Wc_CamelliaSetKey(cam *C.struct_wc_Camellia, key []byte, length int, iv []byte) int {
	if length < 0 || length > len(key) {
		return BAD_FUNC_ARG
	}
	if len(key) == 0 {
		return BAD_FUNC_ARG
	}
	var ivPtr *C.uchar
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	return int(C.wc_CamelliaSetKey(cam, (*C.uchar)(unsafe.Pointer(&key[0])),
		C.word32(length), ivPtr))
}

func Wc_CamelliaSetIV(cam *C.struct_wc_Camellia, iv []byte) int {
	var ivPtr *C.uchar
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	return int(C.wc_CamelliaSetIV(cam, ivPtr))
}

func Wc_CamelliaEncryptDirect(cam *C.struct_wc_Camellia, out []byte, in []byte) int {
	if len(out) < WC_CAMELLIA_BLOCK_SIZE {
		return BAD_FUNC_ARG
	}
	if len(in) < WC_CAMELLIA_BLOCK_SIZE {
		return BAD_FUNC_ARG
	}
	return int(C.wc_CamelliaEncryptDirect(cam,
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&in[0]))))
}

func Wc_CamelliaDecryptDirect(cam *C.struct_wc_Camellia, out []byte, in []byte) int {
	if len(out) < WC_CAMELLIA_BLOCK_SIZE {
		return BAD_FUNC_ARG
	}
	if len(in) < WC_CAMELLIA_BLOCK_SIZE {
		return BAD_FUNC_ARG
	}
	return int(C.wc_CamelliaDecryptDirect(cam,
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&in[0]))))
}

func Wc_CamelliaCbcEncrypt(cam *C.struct_wc_Camellia, out []byte, in []byte, sz int) int {
	if sz < 0 || sz > len(in) {
		return BAD_FUNC_ARG
	}
	if len(out) < sz {
		return BAD_FUNC_ARG
	}
	if sz == 0 {
		return 0
	}
	return int(C.wc_CamelliaCbcEncrypt(cam,
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&in[0])),
		C.word32(sz)))
}

func Wc_CamelliaCbcDecrypt(cam *C.struct_wc_Camellia, out []byte, in []byte, sz int) int {
	if sz < 0 || sz > len(in) {
		return BAD_FUNC_ARG
	}
	if len(out) < sz {
		return BAD_FUNC_ARG
	}
	if sz == 0 {
		return 0
	}
	return int(C.wc_CamelliaCbcDecrypt(cam,
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&in[0])),
		C.word32(sz)))
}
