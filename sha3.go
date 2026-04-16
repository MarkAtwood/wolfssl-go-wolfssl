/* sha3.go
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
// #include <wolfssl/wolfcrypt/sha3.h>
// #ifndef WOLFSSL_SHA3
// #define WC_SHA3_224_DIGEST_SIZE 1
// #define WC_SHA3_256_DIGEST_SIZE 1
// #define WC_SHA3_384_DIGEST_SIZE 1
// #define WC_SHA3_512_DIGEST_SIZE 1
// static int wc_go_InitSha3_224(wc_Sha3* sha3, void* heap, int devId) {
//     (void)sha3; (void)heap; (void)devId; return -174;
// }
// static int wc_go_Sha3_224_Update(wc_Sha3* sha3, const byte* data, word32 len) {
//     (void)sha3; (void)data; (void)len; return -174;
// }
// static int wc_go_Sha3_224_Final(wc_Sha3* sha3, byte* hash) {
//     (void)sha3; (void)hash; return -174;
// }
// static void wc_go_Sha3_224_Free(wc_Sha3* sha3) { (void)sha3; }
// static int wc_go_InitSha3_256(wc_Sha3* sha3, void* heap, int devId) {
//     (void)sha3; (void)heap; (void)devId; return -174;
// }
// static int wc_go_Sha3_256_Update(wc_Sha3* sha3, const byte* data, word32 len) {
//     (void)sha3; (void)data; (void)len; return -174;
// }
// static int wc_go_Sha3_256_Final(wc_Sha3* sha3, byte* hash) {
//     (void)sha3; (void)hash; return -174;
// }
// static void wc_go_Sha3_256_Free(wc_Sha3* sha3) { (void)sha3; }
// static int wc_go_InitSha3_384(wc_Sha3* sha3, void* heap, int devId) {
//     (void)sha3; (void)heap; (void)devId; return -174;
// }
// static int wc_go_Sha3_384_Update(wc_Sha3* sha3, const byte* data, word32 len) {
//     (void)sha3; (void)data; (void)len; return -174;
// }
// static int wc_go_Sha3_384_Final(wc_Sha3* sha3, byte* hash) {
//     (void)sha3; (void)hash; return -174;
// }
// static void wc_go_Sha3_384_Free(wc_Sha3* sha3) { (void)sha3; }
// static int wc_go_InitSha3_512(wc_Sha3* sha3, void* heap, int devId) {
//     (void)sha3; (void)heap; (void)devId; return -174;
// }
// static int wc_go_Sha3_512_Update(wc_Sha3* sha3, const byte* data, word32 len) {
//     (void)sha3; (void)data; (void)len; return -174;
// }
// static int wc_go_Sha3_512_Final(wc_Sha3* sha3, byte* hash) {
//     (void)sha3; (void)hash; return -174;
// }
// static void wc_go_Sha3_512_Free(wc_Sha3* sha3) { (void)sha3; }
// #else
// static int wc_go_InitSha3_224(wc_Sha3* sha3, void* heap, int devId) {
//     return wc_InitSha3_224(sha3, heap, devId);
// }
// static int wc_go_Sha3_224_Update(wc_Sha3* sha3, const byte* data, word32 len) {
//     return wc_Sha3_224_Update(sha3, data, len);
// }
// static int wc_go_Sha3_224_Final(wc_Sha3* sha3, byte* hash) {
//     return wc_Sha3_224_Final(sha3, hash);
// }
// static void wc_go_Sha3_224_Free(wc_Sha3* sha3) { wc_Sha3_224_Free(sha3); }
// static int wc_go_InitSha3_256(wc_Sha3* sha3, void* heap, int devId) {
//     return wc_InitSha3_256(sha3, heap, devId);
// }
// static int wc_go_Sha3_256_Update(wc_Sha3* sha3, const byte* data, word32 len) {
//     return wc_Sha3_256_Update(sha3, data, len);
// }
// static int wc_go_Sha3_256_Final(wc_Sha3* sha3, byte* hash) {
//     return wc_Sha3_256_Final(sha3, hash);
// }
// static void wc_go_Sha3_256_Free(wc_Sha3* sha3) { wc_Sha3_256_Free(sha3); }
// static int wc_go_InitSha3_384(wc_Sha3* sha3, void* heap, int devId) {
//     return wc_InitSha3_384(sha3, heap, devId);
// }
// static int wc_go_Sha3_384_Update(wc_Sha3* sha3, const byte* data, word32 len) {
//     return wc_Sha3_384_Update(sha3, data, len);
// }
// static int wc_go_Sha3_384_Final(wc_Sha3* sha3, byte* hash) {
//     return wc_Sha3_384_Final(sha3, hash);
// }
// static void wc_go_Sha3_384_Free(wc_Sha3* sha3) { wc_Sha3_384_Free(sha3); }
// static int wc_go_InitSha3_512(wc_Sha3* sha3, void* heap, int devId) {
//     return wc_InitSha3_512(sha3, heap, devId);
// }
// static int wc_go_Sha3_512_Update(wc_Sha3* sha3, const byte* data, word32 len) {
//     return wc_Sha3_512_Update(sha3, data, len);
// }
// static int wc_go_Sha3_512_Final(wc_Sha3* sha3, byte* hash) {
//     return wc_Sha3_512_Final(sha3, hash);
// }
// static void wc_go_Sha3_512_Free(wc_Sha3* sha3) { wc_Sha3_512_Free(sha3); }
// #endif
// #ifndef WOLFSSL_SHAKE128
// static int wc_go_InitShake128(wc_Sha3* shake, void* heap, int devId) {
//     (void)shake; (void)heap; (void)devId; return -174;
// }
// static int wc_go_Shake128_Update(wc_Sha3* shake, const byte* data, word32 len) {
//     (void)shake; (void)data; (void)len; return -174;
// }
// static int wc_go_Shake128_Final(wc_Sha3* shake, byte* hash, word32 hashLen) {
//     (void)shake; (void)hash; (void)hashLen; return -174;
// }
// static void wc_go_Shake128_Free(wc_Sha3* shake) { (void)shake; }
// #else
// static int wc_go_InitShake128(wc_Sha3* shake, void* heap, int devId) {
//     return wc_InitShake128(shake, heap, devId);
// }
// static int wc_go_Shake128_Update(wc_Sha3* shake, const byte* data, word32 len) {
//     return wc_Shake128_Update(shake, data, len);
// }
// static int wc_go_Shake128_Final(wc_Sha3* shake, byte* hash, word32 hashLen) {
//     return wc_Shake128_Final(shake, hash, hashLen);
// }
// static void wc_go_Shake128_Free(wc_Sha3* shake) { wc_Shake128_Free(shake); }
// #endif
// #ifndef WOLFSSL_SHAKE256
// static int wc_go_InitShake256(wc_Sha3* shake, void* heap, int devId) {
//     (void)shake; (void)heap; (void)devId; return -174;
// }
// static int wc_go_Shake256_Update(wc_Sha3* shake, const byte* data, word32 len) {
//     (void)shake; (void)data; (void)len; return -174;
// }
// static int wc_go_Shake256_Final(wc_Sha3* shake, byte* hash, word32 hashLen) {
//     (void)shake; (void)hash; (void)hashLen; return -174;
// }
// static void wc_go_Shake256_Free(wc_Sha3* shake) { (void)shake; }
// #else
// static int wc_go_InitShake256(wc_Sha3* shake, void* heap, int devId) {
//     return wc_InitShake256(shake, heap, devId);
// }
// static int wc_go_Shake256_Update(wc_Sha3* shake, const byte* data, word32 len) {
//     return wc_Shake256_Update(shake, data, len);
// }
// static int wc_go_Shake256_Final(wc_Sha3* shake, byte* hash, word32 hashLen) {
//     return wc_Shake256_Final(shake, hash, hashLen);
// }
// static void wc_go_Shake256_Free(wc_Sha3* shake) { wc_Shake256_Free(shake); }
// #endif
import "C"
import (
	"unsafe"
)

type Wc_Sha3 = C.struct_wc_Sha3

const WC_SHA3_224_DIGEST_SIZE = int(C.WC_SHA3_224_DIGEST_SIZE)
const WC_SHA3_256_DIGEST_SIZE = int(C.WC_SHA3_256_DIGEST_SIZE)
const WC_SHA3_384_DIGEST_SIZE = int(C.WC_SHA3_384_DIGEST_SIZE)
const WC_SHA3_512_DIGEST_SIZE = int(C.WC_SHA3_512_DIGEST_SIZE)

// SHA-3 224

func Wc_InitSha3_224(sha3 *C.struct_wc_Sha3, heap unsafe.Pointer, devId int) int {
	return int(C.wc_go_InitSha3_224(sha3, heap, C.int(devId)))
}

func Wc_Sha3_224Update(sha3 *C.struct_wc_Sha3, in []byte, inSz int) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	var sanIn *C.uchar
	if len(in) > 0 {
		sanIn = (*C.uchar)(unsafe.Pointer(&in[0]))
	} else {
		sanIn = (*C.uchar)(unsafe.Pointer(nil))
	}
	return int(C.wc_go_Sha3_224_Update(sha3, sanIn, C.word32(inSz)))
}

func Wc_Sha3_224Final(sha3 *C.struct_wc_Sha3, out []byte) int {
	if len(out) < WC_SHA3_224_DIGEST_SIZE {
		return BAD_FUNC_ARG
	}
	return int(C.wc_go_Sha3_224_Final(sha3, (*C.uchar)(unsafe.Pointer(&out[0]))))
}

func Wc_Sha3_224Free(sha3 *C.struct_wc_Sha3) {
	C.wc_go_Sha3_224_Free(sha3)
}

// SHA-3 256

func Wc_InitSha3_256(sha3 *C.struct_wc_Sha3, heap unsafe.Pointer, devId int) int {
	return int(C.wc_go_InitSha3_256(sha3, heap, C.int(devId)))
}

func Wc_Sha3_256Update(sha3 *C.struct_wc_Sha3, in []byte, inSz int) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	var sanIn *C.uchar
	if len(in) > 0 {
		sanIn = (*C.uchar)(unsafe.Pointer(&in[0]))
	} else {
		sanIn = (*C.uchar)(unsafe.Pointer(nil))
	}
	return int(C.wc_go_Sha3_256_Update(sha3, sanIn, C.word32(inSz)))
}

func Wc_Sha3_256Final(sha3 *C.struct_wc_Sha3, out []byte) int {
	if len(out) < WC_SHA3_256_DIGEST_SIZE {
		return BAD_FUNC_ARG
	}
	return int(C.wc_go_Sha3_256_Final(sha3, (*C.uchar)(unsafe.Pointer(&out[0]))))
}

func Wc_Sha3_256Free(sha3 *C.struct_wc_Sha3) {
	C.wc_go_Sha3_256_Free(sha3)
}

// SHA-3 384

func Wc_InitSha3_384(sha3 *C.struct_wc_Sha3, heap unsafe.Pointer, devId int) int {
	return int(C.wc_go_InitSha3_384(sha3, heap, C.int(devId)))
}

func Wc_Sha3_384Update(sha3 *C.struct_wc_Sha3, in []byte, inSz int) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	var sanIn *C.uchar
	if len(in) > 0 {
		sanIn = (*C.uchar)(unsafe.Pointer(&in[0]))
	} else {
		sanIn = (*C.uchar)(unsafe.Pointer(nil))
	}
	return int(C.wc_go_Sha3_384_Update(sha3, sanIn, C.word32(inSz)))
}

func Wc_Sha3_384Final(sha3 *C.struct_wc_Sha3, out []byte) int {
	if len(out) < WC_SHA3_384_DIGEST_SIZE {
		return BAD_FUNC_ARG
	}
	return int(C.wc_go_Sha3_384_Final(sha3, (*C.uchar)(unsafe.Pointer(&out[0]))))
}

func Wc_Sha3_384Free(sha3 *C.struct_wc_Sha3) {
	C.wc_go_Sha3_384_Free(sha3)
}

// SHA-3 512

func Wc_InitSha3_512(sha3 *C.struct_wc_Sha3, heap unsafe.Pointer, devId int) int {
	return int(C.wc_go_InitSha3_512(sha3, heap, C.int(devId)))
}

func Wc_Sha3_512Update(sha3 *C.struct_wc_Sha3, in []byte, inSz int) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	var sanIn *C.uchar
	if len(in) > 0 {
		sanIn = (*C.uchar)(unsafe.Pointer(&in[0]))
	} else {
		sanIn = (*C.uchar)(unsafe.Pointer(nil))
	}
	return int(C.wc_go_Sha3_512_Update(sha3, sanIn, C.word32(inSz)))
}

func Wc_Sha3_512Final(sha3 *C.struct_wc_Sha3, out []byte) int {
	if len(out) < WC_SHA3_512_DIGEST_SIZE {
		return BAD_FUNC_ARG
	}
	return int(C.wc_go_Sha3_512_Final(sha3, (*C.uchar)(unsafe.Pointer(&out[0]))))
}

func Wc_Sha3_512Free(sha3 *C.struct_wc_Sha3) {
	C.wc_go_Sha3_512_Free(sha3)
}

// SHAKE-128

func Wc_InitShake128(shake *C.struct_wc_Sha3, heap unsafe.Pointer, devId int) int {
	return int(C.wc_go_InitShake128(shake, heap, C.int(devId)))
}

func Wc_Shake128Update(shake *C.struct_wc_Sha3, in []byte, inSz int) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	var sanIn *C.uchar
	if len(in) > 0 {
		sanIn = (*C.uchar)(unsafe.Pointer(&in[0]))
	} else {
		sanIn = (*C.uchar)(unsafe.Pointer(nil))
	}
	return int(C.wc_go_Shake128_Update(shake, sanIn, C.word32(inSz)))
}

func Wc_Shake128Final(shake *C.struct_wc_Sha3, out []byte, hashSz int) int {
	if hashSz <= 0 || hashSz > len(out) {
		return BAD_FUNC_ARG
	}
	return int(C.wc_go_Shake128_Final(shake, (*C.uchar)(unsafe.Pointer(&out[0])), C.word32(hashSz)))
}

func Wc_Shake128Free(shake *C.struct_wc_Sha3) {
	C.wc_go_Shake128_Free(shake)
}

// SHAKE-256

func Wc_InitShake256(shake *C.struct_wc_Sha3, heap unsafe.Pointer, devId int) int {
	return int(C.wc_go_InitShake256(shake, heap, C.int(devId)))
}

func Wc_Shake256Update(shake *C.struct_wc_Sha3, in []byte, inSz int) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	var sanIn *C.uchar
	if len(in) > 0 {
		sanIn = (*C.uchar)(unsafe.Pointer(&in[0]))
	} else {
		sanIn = (*C.uchar)(unsafe.Pointer(nil))
	}
	return int(C.wc_go_Shake256_Update(shake, sanIn, C.word32(inSz)))
}

func Wc_Shake256Final(shake *C.struct_wc_Sha3, out []byte, hashSz int) int {
	if hashSz <= 0 || hashSz > len(out) {
		return BAD_FUNC_ARG
	}
	return int(C.wc_go_Shake256_Final(shake, (*C.uchar)(unsafe.Pointer(&out[0])), C.word32(hashSz)))
}

func Wc_Shake256Free(shake *C.struct_wc_Sha3) {
	C.wc_go_Shake256_Free(shake)
}
