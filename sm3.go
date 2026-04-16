/* sm3.go
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

// SM3 is part of the commercial wolfsm extension (https://github.com/wolfSSL/wolfsm).
// The wolfssl/wolfcrypt/sm3.h header in the open-source tree contains only a
// compile-time error directing users to wolfsm. Stubs are provided here so that
// this package builds regardless of whether WOLFSSL_SM3 is defined; callers
// will receive -174 (NOT_COMPILED_IN) from every function.

package wolfSSL

// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/options.h>
// #define WC_SM3_DIGEST_SIZE 32
// typedef struct wc_Sm3 { int dummy; } wc_Sm3;
// static int wc_InitSm3(wc_Sm3* sm3, void* heap, int devId) {
//     (void)sm3; (void)heap; (void)devId; return -174;
// }
// static int wc_Sm3Update(wc_Sm3* sm3, const unsigned char* in, unsigned int inSz) {
//     (void)sm3; (void)in; (void)inSz; return -174;
// }
// static int wc_Sm3Final(wc_Sm3* sm3, unsigned char* out) {
//     (void)sm3; (void)out; return -174;
// }
// static void wc_Sm3Free(wc_Sm3* sm3) {
//     (void)sm3;
// }
// static int wc_Sm3Hash(const unsigned char* in, unsigned int inSz,
//                       unsigned char* out) {
//     (void)in; (void)inSz; (void)out; return -174;
// }
import "C"
import "unsafe"

const WC_SM3_DIGEST_SIZE = int(C.WC_SM3_DIGEST_SIZE)

type Wc_Sm3 = C.struct_wc_Sm3

func Wc_InitSm3(sm3 *C.struct_wc_Sm3, devId int) int {
	return int(C.wc_InitSm3(sm3, unsafe.Pointer(nil), C.int(devId)))
}

func Wc_Sm3Update(sm3 *C.struct_wc_Sm3, in []byte, inSz int) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	var inPtr *C.uchar
	if len(in) > 0 {
		inPtr = (*C.uchar)(unsafe.Pointer(&in[0]))
	}
	return int(C.wc_Sm3Update(sm3, inPtr, C.uint(inSz)))
}

func Wc_Sm3Final(sm3 *C.struct_wc_Sm3, out []byte) int {
	if len(out) < WC_SM3_DIGEST_SIZE {
		return BAD_FUNC_ARG
	}
	return int(C.wc_Sm3Final(sm3, (*C.uchar)(unsafe.Pointer(&out[0]))))
}

func Wc_Sm3Free(sm3 *C.struct_wc_Sm3) {
	C.wc_Sm3Free(sm3)
}

func Wc_Sm3Hash(in []byte, inSz int, out []byte) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	if len(out) < WC_SM3_DIGEST_SIZE {
		return BAD_FUNC_ARG
	}
	var inPtr *C.uchar
	if len(in) > 0 {
		inPtr = (*C.uchar)(unsafe.Pointer(&in[0]))
	}
	return int(C.wc_Sm3Hash(inPtr, C.uint(inSz),
		(*C.uchar)(unsafe.Pointer(&out[0]))))
}
