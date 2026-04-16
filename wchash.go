/* wchash.go
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
// #include <wolfssl/wolfcrypt/hash.h>
// #ifdef NO_HASH_WRAPPER
// #define WC_MAX_DIGEST_SIZE 1
// static int wc_HashGetDigestSize_shim(int hashType) { return -174; }
// static int wc_HashGetBlockSize_shim(int hashType) { return -174; }
// static int wc_Hash_shim(int hashType,
//     const byte* data, word32 dataLen,
//     byte* hash, word32 hashLen) { return -174; }
// static int wc_HashInit_shim(wc_HashAlg* hashAlg, int hashType) {
//     (void)hashAlg; (void)hashType; return -174;
// }
// static int wc_HashUpdate_shim(wc_HashAlg* hashAlg, int hashType,
//     const byte* data, word32 dataSz) {
//     (void)hashAlg; (void)hashType; (void)data; (void)dataSz; return -174;
// }
// static int wc_HashFinal_shim(wc_HashAlg* hashAlg, int hashType,
//     byte* out) { (void)hashAlg; (void)hashType; (void)out; return -174; }
// static int wc_HashFree_shim(wc_HashAlg* hashAlg, int hashType) {
//     (void)hashAlg; (void)hashType; return -174;
// }
// #else
// static int wc_HashGetDigestSize_shim(int hashType) {
//     return wc_HashGetDigestSize((enum wc_HashType)hashType);
// }
// static int wc_HashGetBlockSize_shim(int hashType) {
//     return wc_HashGetBlockSize((enum wc_HashType)hashType);
// }
// static int wc_Hash_shim(int hashType,
//     const byte* data, word32 dataLen,
//     byte* hash, word32 hashLen) {
//     return wc_Hash((enum wc_HashType)hashType, data, dataLen, hash, hashLen);
// }
// static int wc_HashInit_shim(wc_HashAlg* hashAlg, int hashType) {
//     return wc_HashInit(hashAlg, (enum wc_HashType)hashType);
// }
// static int wc_HashUpdate_shim(wc_HashAlg* hashAlg, int hashType,
//     const byte* data, word32 dataSz) {
//     return wc_HashUpdate(hashAlg, (enum wc_HashType)hashType, data, dataSz);
// }
// static int wc_HashFinal_shim(wc_HashAlg* hashAlg, int hashType,
//     byte* out) {
//     return wc_HashFinal(hashAlg, (enum wc_HashType)hashType, out);
// }
// static int wc_HashFree_shim(wc_HashAlg* hashAlg, int hashType) {
//     return wc_HashFree(hashAlg, (enum wc_HashType)hashType);
// }
// #endif
import "C"
import (
	"unsafe"
)

// WcHashType is the wolfcrypt hash algorithm selector.
type WcHashType = C.enum_wc_HashType

// WcHashAlg is the wolfcrypt generic streaming hash context.
type WcHashAlg = C.wc_HashAlg

const WC_MAX_DIGEST_SIZE = int(C.WC_MAX_DIGEST_SIZE)

// WcHashType constants mirroring wc_HashType enum values.
const (
	WC_HASH_TYPE_NONE     = int(C.WC_HASH_TYPE_NONE)
	WC_HASH_TYPE_MD5      = int(C.WC_HASH_TYPE_MD5)
	WC_HASH_TYPE_SHA      = int(C.WC_HASH_TYPE_SHA)
	WC_HASH_TYPE_SHA224   = int(C.WC_HASH_TYPE_SHA224)
	WC_HASH_TYPE_SHA256   = int(C.WC_HASH_TYPE_SHA256)
	WC_HASH_TYPE_SHA384   = int(C.WC_HASH_TYPE_SHA384)
	WC_HASH_TYPE_SHA512   = int(C.WC_HASH_TYPE_SHA512)
	WC_HASH_TYPE_SHA3_224 = int(C.WC_HASH_TYPE_SHA3_224)
	WC_HASH_TYPE_SHA3_256 = int(C.WC_HASH_TYPE_SHA3_256)
	WC_HASH_TYPE_SHA3_384 = int(C.WC_HASH_TYPE_SHA3_384)
	WC_HASH_TYPE_SHA3_512 = int(C.WC_HASH_TYPE_SHA3_512)
)

// Wc_HashGetDigestSize returns the digest size in bytes for the given hash
// type, or a negative wolfcrypt error code on failure.
func Wc_HashGetDigestSize(hashType int) int {
	return int(C.wc_HashGetDigestSize_shim(C.int(hashType)))
}

// Wc_HashGetBlockSize returns the block size in bytes for the given hash
// type, or a negative wolfcrypt error code on failure.
func Wc_HashGetBlockSize(hashType int) int {
	return int(C.wc_HashGetBlockSize_shim(C.int(hashType)))
}

// Wc_Hash computes a one-shot hash of data using the given hash type and
// writes the digest into output. output must be at least
// Wc_HashGetDigestSize(hashType) bytes. Returns 0 on success.
func Wc_Hash(hashType int, input []byte, inputSz int, output []byte) int {
	if inputSz < 0 || inputSz > len(input) {
		return BAD_FUNC_ARG
	}
	digestSz := Wc_HashGetDigestSize(hashType)
	if digestSz <= 0 {
		return BAD_FUNC_ARG
	}
	if len(output) < digestSz {
		return BAD_FUNC_ARG
	}
	var sanIn *C.uchar
	if len(input) > 0 {
		sanIn = (*C.uchar)(unsafe.Pointer(&input[0]))
	}
	return int(C.wc_Hash_shim(C.int(hashType),
		sanIn, C.word32(inputSz),
		(*C.uchar)(unsafe.Pointer(&output[0])), C.word32(digestSz)))
}

// Wc_HashInit initializes a wc_HashAlg streaming context for the given hash
// type. The caller must call Wc_HashFree when done. Returns 0 on success.
func Wc_HashInit(hashAlg *WcHashAlg, hashType int) int {
	return int(C.wc_HashInit_shim(hashAlg, C.int(hashType)))
}

// Wc_HashUpdate feeds data into an initialized wc_HashAlg context.
// Returns 0 on success.
func Wc_HashUpdate(hashAlg *WcHashAlg, hashType int, input []byte, inputSz int) int {
	if inputSz < 0 || inputSz > len(input) {
		return BAD_FUNC_ARG
	}
	var sanIn *C.uchar
	if inputSz > 0 {
		sanIn = (*C.uchar)(unsafe.Pointer(&input[0]))
	}
	return int(C.wc_HashUpdate_shim(hashAlg, C.int(hashType),
		sanIn, C.word32(inputSz)))
}

// Wc_HashFinal finalizes the hash and writes the digest to output.
// output must be at least Wc_HashGetDigestSize(hashType) bytes.
// Returns 0 on success.
func Wc_HashFinal(hashAlg *WcHashAlg, hashType int, output []byte) int {
	digestSz := Wc_HashGetDigestSize(hashType)
	if digestSz <= 0 {
		return BAD_FUNC_ARG
	}
	if len(output) < digestSz {
		return BAD_FUNC_ARG
	}
	return int(C.wc_HashFinal_shim(hashAlg, C.int(hashType),
		(*C.uchar)(unsafe.Pointer(&output[0]))))
}

// Wc_HashFree releases resources held by a wc_HashAlg context.
// Returns 0 on success.
func Wc_HashFree(hashAlg *WcHashAlg, hashType int) int {
	return int(C.wc_HashFree_shim(hashAlg, C.int(hashType)))
}
