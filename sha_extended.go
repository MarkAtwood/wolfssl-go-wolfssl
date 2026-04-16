/* sha_extended.go
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
// #include <wolfssl/wolfcrypt/sha.h>
// #include <wolfssl/wolfcrypt/sha256.h>
// #include <wolfssl/wolfcrypt/sha512.h>
//
// #ifdef NO_SHA
// #define WC_SHA_DIGEST_SIZE_STUB 1
// static int wc_go_InitSha(wc_Sha* sha) { (void)sha; return -174; }
// static int wc_go_ShaUpdate(wc_Sha* sha, const byte* d, word32 l) { (void)sha; (void)d; (void)l; return -174; }
// static int wc_go_ShaFinal(wc_Sha* sha, byte* h) { (void)sha; (void)h; return -174; }
// static void wc_go_ShaFree(wc_Sha* sha) { (void)sha; }
// #else
// static int wc_go_InitSha(wc_Sha* sha) { return wc_InitSha(sha); }
// static int wc_go_ShaUpdate(wc_Sha* sha, const byte* d, word32 l) { return wc_ShaUpdate(sha, d, l); }
// static int wc_go_ShaFinal(wc_Sha* sha, byte* h) { return wc_ShaFinal(sha, h); }
// static void wc_go_ShaFree(wc_Sha* sha) { wc_ShaFree(sha); }
// #endif
//
// #ifndef WOLFSSL_SHA224
// static int wc_go_InitSha224(struct wc_Sha256* sha) { (void)sha; return -174; }
// static int wc_go_Sha224Update(struct wc_Sha256* sha, const byte* d, word32 l) { (void)sha; (void)d; (void)l; return -174; }
// static int wc_go_Sha224Final(struct wc_Sha256* sha, byte* h) { (void)sha; (void)h; return -174; }
// static void wc_go_Sha224Free(struct wc_Sha256* sha) { (void)sha; }
// #else
// static int wc_go_InitSha224(struct wc_Sha256* sha) { return wc_InitSha224(sha); }
// static int wc_go_Sha224Update(struct wc_Sha256* sha, const byte* d, word32 l) { return wc_Sha224Update(sha, d, l); }
// static int wc_go_Sha224Final(struct wc_Sha256* sha, byte* h) { return wc_Sha224Final(sha, h); }
// static void wc_go_Sha224Free(struct wc_Sha256* sha) { wc_Sha224Free(sha); }
// #endif
//
// #ifndef WOLFSSL_SHA384
// static int wc_go_InitSha384(struct wc_Sha512* sha) { (void)sha; return -174; }
// static int wc_go_Sha384Update(struct wc_Sha512* sha, const byte* d, word32 l) { (void)sha; (void)d; (void)l; return -174; }
// static int wc_go_Sha384Final(struct wc_Sha512* sha, byte* h) { (void)sha; (void)h; return -174; }
// static void wc_go_Sha384Free(struct wc_Sha512* sha) { (void)sha; }
// #else
// static int wc_go_InitSha384(struct wc_Sha512* sha) { return wc_InitSha384(sha); }
// static int wc_go_Sha384Update(struct wc_Sha512* sha, const byte* d, word32 l) { return wc_Sha384Update(sha, d, l); }
// static int wc_go_Sha384Final(struct wc_Sha512* sha, byte* h) { return wc_Sha384Final(sha, h); }
// static void wc_go_Sha384Free(struct wc_Sha512* sha) { wc_Sha384Free(sha); }
// #endif
//
// #ifndef WOLFSSL_SHA512
// static int wc_go_InitSha512(wc_Sha512* sha) { (void)sha; return -174; }
// static int wc_go_Sha512Update(wc_Sha512* sha, const byte* d, word32 l) { (void)sha; (void)d; (void)l; return -174; }
// static int wc_go_Sha512Final(wc_Sha512* sha, byte* h) { (void)sha; (void)h; return -174; }
// static void wc_go_Sha512Free(wc_Sha512* sha) { (void)sha; }
// #else
// static int wc_go_InitSha512(wc_Sha512* sha) { return wc_InitSha512(sha); }
// static int wc_go_Sha512Update(wc_Sha512* sha, const byte* d, word32 l) { return wc_Sha512Update(sha, d, l); }
// static int wc_go_Sha512Final(wc_Sha512* sha, byte* h) { return wc_Sha512Final(sha, h); }
// static void wc_go_Sha512Free(wc_Sha512* sha) { wc_Sha512Free(sha); }
// #endif
import "C"
import (
	"unsafe"
)

type Wc_Sha = C.struct_wc_Sha

// wc_Sha224 is a typedef for struct wc_Sha256 in the wolfSSL headers.
type Wc_Sha224 = C.struct_wc_Sha256

// wc_Sha384 is a typedef for struct wc_Sha512 in the wolfSSL headers.
type Wc_Sha384 = C.struct_wc_Sha512
type Wc_Sha512 = C.struct_wc_Sha512

// SHA-1

func Wc_InitSha(sha *C.struct_wc_Sha) int {
	return int(C.wc_go_InitSha(sha))
}

func Wc_ShaFree(sha *C.struct_wc_Sha) {
	C.wc_go_ShaFree(sha)
}

func Wc_ShaUpdate(sha *C.struct_wc_Sha, in []byte, inSz int) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	var sanIn *C.uchar
	if len(in) > 0 {
		sanIn = (*C.uchar)(unsafe.Pointer(&in[0]))
	} else {
		sanIn = (*C.uchar)(unsafe.Pointer(nil))
	}
	return int(C.wc_go_ShaUpdate(sha, sanIn, C.word32(inSz)))
}

func Wc_ShaFinal(sha *C.struct_wc_Sha, out []byte) int {
	if len(out) < WC_SHA_DIGEST_SIZE {
		return -173
	}
	return int(C.wc_go_ShaFinal(sha, (*C.uchar)(unsafe.Pointer(&out[0]))))
}

// SHA-224
// wc_Sha224 is a typedef for struct wc_Sha256; use Wc_Sha224 (= C.struct_wc_Sha256) as the parameter type.

func Wc_InitSha224(sha *Wc_Sha224) int {
	return int(C.wc_go_InitSha224(sha))
}

func Wc_Sha224Free(sha *Wc_Sha224) {
	C.wc_go_Sha224Free(sha)
}

func Wc_Sha224Update(sha *Wc_Sha224, in []byte, inSz int) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	var sanIn *C.uchar
	if len(in) > 0 {
		sanIn = (*C.uchar)(unsafe.Pointer(&in[0]))
	} else {
		sanIn = (*C.uchar)(unsafe.Pointer(nil))
	}
	return int(C.wc_go_Sha224Update(sha, sanIn, C.word32(inSz)))
}

func Wc_Sha224Final(sha *Wc_Sha224, out []byte) int {
	if len(out) < WC_SHA224_DIGEST_SIZE {
		return -173
	}
	return int(C.wc_go_Sha224Final(sha, (*C.uchar)(unsafe.Pointer(&out[0]))))
}

// SHA-384
// wc_Sha384 is a typedef for struct wc_Sha512; use Wc_Sha384 (= C.struct_wc_Sha512) as the parameter type.

func Wc_InitSha384(sha *Wc_Sha384) int {
	return int(C.wc_go_InitSha384(sha))
}

func Wc_Sha384Free(sha *Wc_Sha384) {
	C.wc_go_Sha384Free(sha)
}

func Wc_Sha384Update(sha *Wc_Sha384, in []byte, inSz int) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	var sanIn *C.uchar
	if len(in) > 0 {
		sanIn = (*C.uchar)(unsafe.Pointer(&in[0]))
	} else {
		sanIn = (*C.uchar)(unsafe.Pointer(nil))
	}
	return int(C.wc_go_Sha384Update(sha, sanIn, C.word32(inSz)))
}

func Wc_Sha384Final(sha *Wc_Sha384, out []byte) int {
	if len(out) < WC_SHA384_DIGEST_SIZE {
		return -173
	}
	return int(C.wc_go_Sha384Final(sha, (*C.uchar)(unsafe.Pointer(&out[0]))))
}

// SHA-512

func Wc_InitSha512(sha *C.struct_wc_Sha512) int {
	return int(C.wc_go_InitSha512(sha))
}

func Wc_Sha512Free(sha *C.struct_wc_Sha512) {
	C.wc_go_Sha512Free(sha)
}

func Wc_Sha512Update(sha *C.struct_wc_Sha512, in []byte, inSz int) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	var sanIn *C.uchar
	if len(in) > 0 {
		sanIn = (*C.uchar)(unsafe.Pointer(&in[0]))
	} else {
		sanIn = (*C.uchar)(unsafe.Pointer(nil))
	}
	return int(C.wc_go_Sha512Update(sha, sanIn, C.word32(inSz)))
}

func Wc_Sha512Final(sha *C.struct_wc_Sha512, out []byte) int {
	if len(out) < WC_SHA512_DIGEST_SIZE {
		return -173
	}
	return int(C.wc_go_Sha512Final(sha, (*C.uchar)(unsafe.Pointer(&out[0]))))
}
