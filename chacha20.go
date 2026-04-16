/* chacha20.go
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
// #include <wolfssl/wolfcrypt/chacha.h>
// #ifdef HAVE_CHACHA
// static int wc_Chacha_SetKey_ex(ChaCha* ctx, const byte* key, word32 keySz) {
//     return wc_Chacha_SetKey(ctx, key, keySz);
// }
// static int wc_Chacha_SetIV_ex(ChaCha* ctx, const byte* inIv, word32 counter) {
//     return wc_Chacha_SetIV(ctx, inIv, counter);
// }
// static int wc_Chacha_Process_ex(ChaCha* ctx, byte* cipher, const byte* plain, word32 msglen) {
//     return wc_Chacha_Process(ctx, cipher, plain, msglen);
// }
// #else
// static int wc_Chacha_SetKey_ex(void* ctx, const void* key, unsigned int keySz) {
//     (void)ctx; (void)key; (void)keySz;
//     return -174;
// }
// static int wc_Chacha_SetIV_ex(void* ctx, const void* inIv, unsigned int counter) {
//     (void)ctx; (void)inIv; (void)counter;
//     return -174;
// }
// static int wc_Chacha_Process_ex(void* ctx, void* cipher, const void* plain, unsigned int msglen) {
//     (void)ctx; (void)cipher; (void)plain; (void)msglen;
//     return -174;
// }
// #endif
import "C"
import (
	"unsafe"
)

type ChaCha = C.struct_ChaCha

func Wc_Chacha_SetKey(ctx *C.struct_ChaCha, key []byte, keySz int) int {
	if keySz < 0 || keySz > len(key) {
		return BAD_FUNC_ARG
	}
	var sanKey *C.uchar
	if len(key) > 0 {
		sanKey = (*C.uchar)(unsafe.Pointer(&key[0]))
	} else {
		sanKey = (*C.uchar)(unsafe.Pointer(nil))
	}
	return int(C.wc_Chacha_SetKey_ex(ctx, sanKey, C.word32(keySz)))
}

func Wc_Chacha_SetIV(ctx *C.struct_ChaCha, iv []byte, counter uint32) int {
	if len(iv) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.wc_Chacha_SetIV_ex(ctx, (*C.uchar)(unsafe.Pointer(&iv[0])), C.word32(counter)))
}

func Wc_Chacha_Process(ctx *C.struct_ChaCha, out []byte, in []byte, sz int) int {
	if sz < 0 || sz > len(in) {
		return BAD_FUNC_ARG
	}
	if sz > len(out) {
		return BAD_FUNC_ARG
	}
	var sanIn *C.uchar
	if len(in) > 0 {
		sanIn = (*C.uchar)(unsafe.Pointer(&in[0]))
	} else {
		sanIn = (*C.uchar)(unsafe.Pointer(nil))
	}
	var sanOut *C.uchar
	if len(out) > 0 {
		sanOut = (*C.uchar)(unsafe.Pointer(&out[0]))
	} else {
		sanOut = (*C.uchar)(unsafe.Pointer(nil))
	}
	return int(C.wc_Chacha_Process_ex(ctx, sanOut, sanIn, C.word32(sz)))
}
