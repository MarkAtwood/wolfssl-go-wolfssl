/* ecc_ext.go
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
// #include <wolfssl/wolfcrypt/ecc.h>
// #include <wolfssl/wolfcrypt/random.h>
// #include <wolfssl/wolfcrypt/wolfmath.h>
// #include <stdlib.h>
//
// #ifndef HAVE_ECC
//
// static int wc_ecc_make_key_ex_stub(WC_RNG* rng, int keysize, ecc_key* key,
//                                    int curve_id) {
//     (void)rng; (void)keysize; (void)key; (void)curve_id;
//     return -174;
// }
//
// static int wc_ecc_sign_hash_ex_shim(const byte* in, word32 inlen,
//                                     WC_RNG* rng, ecc_key* key,
//                                     byte* rBuf, word32* rLen,
//                                     byte* sBuf, word32* sLen) {
//     (void)in; (void)inlen; (void)rng; (void)key;
//     (void)rBuf; (void)rLen; (void)sBuf; (void)sLen;
//     return -174;
// }
//
// static int wc_ecc_verify_hash_ex_shim(const byte* rBuf, word32 rLen,
//                                       const byte* sBuf, word32 sLen,
//                                       const byte* hash, word32 hashlen,
//                                       int* res, ecc_key* key) {
//     (void)rBuf; (void)rLen; (void)sBuf; (void)sLen;
//     (void)hash; (void)hashlen; (void)res; (void)key;
//     return -174;
// }
//
// static int wc_ecc_rs_to_sig_stub(const char* r, const char* s, byte* out,
//                                  word32* outlen) {
//     (void)r; (void)s; (void)out; (void)outlen;
//     return -174;
// }
//
// static int wc_ecc_sig_to_rs_stub(const byte* sig, word32 sigLen,
//                                  byte* r, word32* rLen,
//                                  byte* s, word32* sLen) {
//     (void)sig; (void)sigLen; (void)r; (void)rLen; (void)s; (void)sLen;
//     return -174;
// }
//
// static int wc_ecc_point_is_at_infinity_stub(ecc_point* p) {
//     (void)p;
//     return -174;
// }
//
// static int wc_ecc_point_is_on_curve_stub(ecc_point* p, int curve_idx) {
//     (void)p; (void)curve_idx;
//     return -174;
// }
//
// static int wc_ecc_get_curve_id_stub(int curve_idx) {
//     (void)curve_idx;
//     return -174;
// }
//
// static int wc_ecc_get_curve_id_from_name_stub(const char* curveName) {
//     (void)curveName;
//     return -174;
// }
//
// static int wc_ecc_get_curve_size_from_id_stub(int curve_id) {
//     (void)curve_id;
//     return -174;
// }
//
// #else /* HAVE_ECC */
//
// /* wc_ecc_sign_hash_ex uses mp_int* for r and s.  We expose a shim that
//  * encodes those bignums into big-endian raw byte buffers so Go code does
//  * not need to deal with the mp_int type directly.
//  * wolfmath.h is already pulled in via ecc.h, so mp_int is available. */
//
// static int wc_ecc_sign_hash_ex_shim(const byte* in, word32 inlen,
//                                     WC_RNG* rng, ecc_key* key,
//                                     byte* rBuf, word32* rLen,
//                                     byte* sBuf, word32* sLen) {
//     mp_int r, s;
//     int ret;
//     word32 keySz;
//
//     ret = mp_init(&r);
//     if (ret != 0) return ret;
//     ret = mp_init(&s);
//     if (ret != 0) { mp_free(&r); return ret; }
//
//     ret = wc_ecc_sign_hash_ex(in, inlen, rng, key, &r, &s);
//     if (ret == 0) {
//         keySz = (word32)wc_ecc_size(key);
//         if (*rLen < keySz || *sLen < keySz) {
//             ret = -174; /* buffer too small */
//         } else {
//             ret = mp_to_unsigned_bin_len(&r, rBuf, (int)keySz);
//             if (ret == 0) {
//                 *rLen = keySz;
//                 ret = mp_to_unsigned_bin_len(&s, sBuf, (int)keySz);
//                 if (ret == 0) *sLen = keySz;
//             }
//         }
//     }
//
//     mp_free(&s);
//     mp_free(&r);
//     return ret;
// }
//
// /* wc_ecc_verify_hash_ex uses mp_int* for r and s.  Accept raw big-endian
//  * byte buffers and convert to mp_int before calling the real function. */
// static int wc_ecc_verify_hash_ex_shim(const byte* rBuf, word32 rLen,
//                                       const byte* sBuf, word32 sLen,
//                                       const byte* hash, word32 hashlen,
//                                       int* res, ecc_key* key) {
//     mp_int r, s;
//     int ret;
//
//     ret = mp_init(&r);
//     if (ret != 0) return ret;
//     ret = mp_init(&s);
//     if (ret != 0) { mp_free(&r); return ret; }
//
//     ret = mp_read_unsigned_bin(&r, rBuf, rLen);
//     if (ret == 0) ret = mp_read_unsigned_bin(&s, sBuf, sLen);
//     if (ret == 0) ret = wc_ecc_verify_hash_ex(&r, &s, hash, hashlen, res, key);
//
//     mp_free(&s);
//     mp_free(&r);
//     return ret;
// }
//
// /* Thin wrappers with the same name as the stubs but forwarding to the real API */
// static int wc_ecc_make_key_ex_stub(WC_RNG* rng, int keysize, ecc_key* key,
//                                    int curve_id) {
//     return wc_ecc_make_key_ex(rng, keysize, key, curve_id);
// }
//
// static int wc_ecc_rs_to_sig_stub(const char* r, const char* s, byte* out,
//                                  word32* outlen) {
//     return wc_ecc_rs_to_sig(r, s, out, outlen);
// }
//
// static int wc_ecc_sig_to_rs_stub(const byte* sig, word32 sigLen,
//                                  byte* r, word32* rLen,
//                                  byte* s, word32* sLen) {
//     return wc_ecc_sig_to_rs(sig, sigLen, r, rLen, s, sLen);
// }
//
// static int wc_ecc_point_is_at_infinity_stub(ecc_point* p) {
//     return wc_ecc_point_is_at_infinity(p);
// }
//
// static int wc_ecc_point_is_on_curve_stub(ecc_point* p, int curve_idx) {
//     return wc_ecc_point_is_on_curve(p, curve_idx);
// }
//
// static int wc_ecc_get_curve_id_stub(int curve_idx) {
//     return wc_ecc_get_curve_id(curve_idx);
// }
//
// static int wc_ecc_get_curve_id_from_name_stub(const char* curveName) {
//     return wc_ecc_get_curve_id_from_name(curveName);
// }
//
// static int wc_ecc_get_curve_size_from_id_stub(int curve_id) {
//     return wc_ecc_get_curve_size_from_id(curve_id);
// }
//
// #endif /* HAVE_ECC */
import "C"
import (
	"unsafe"
)

// Wc_ecc_make_key_ex creates an ECC key for the specified curve ID.
// Use ECC_CURVE_DEF (0) for the default curve matching keysize.
func Wc_ecc_make_key_ex(rng *C.struct_WC_RNG, keySize int, key *C.struct_ecc_key, curveID int) int {
	return int(C.wc_ecc_make_key_ex_stub(rng, C.int(keySize), key, C.int(curveID)))
}

// Wc_ecc_sign_hash_ex signs a hash and returns the raw big-endian R and S
// components. rBuf and sBuf must each be at least wc_ecc_size(key) bytes.
// On success, rLen and sLen are updated to the actual component lengths.
func Wc_ecc_sign_hash_ex(in []byte, inLen int, rng *C.struct_WC_RNG, key *C.struct_ecc_key,
	rBuf []byte, rLen *int, sBuf []byte, sLen *int) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if rLen == nil || sLen == nil {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 || len(rBuf) == 0 || len(sBuf) == 0 {
		return BAD_FUNC_ARG
	}
	if *rLen < 0 || *rLen > len(rBuf) || *sLen < 0 || *sLen > len(sBuf) {
		return BAD_FUNC_ARG
	}
	cRLen := C.word32(*rLen)
	cSLen := C.word32(*sLen)
	ret := int(C.wc_ecc_sign_hash_ex_shim(
		(*C.uchar)(unsafe.Pointer(&in[0])), C.word32(inLen),
		rng, key,
		(*C.uchar)(unsafe.Pointer(&rBuf[0])), &cRLen,
		(*C.uchar)(unsafe.Pointer(&sBuf[0])), &cSLen,
	))
	*rLen = int(cRLen)
	*sLen = int(cSLen)
	return ret
}

// Wc_ecc_verify_hash_ex verifies a signature given raw big-endian R and S
// components. On success res is set to 1 (valid) or 0 (invalid).
func Wc_ecc_verify_hash_ex(rBuf []byte, rLen int, sBuf []byte, sLen int,
	hash []byte, hashLen int, res *int, key *C.struct_ecc_key) int {
	if rLen < 0 || rLen > len(rBuf) {
		return BAD_FUNC_ARG
	}
	if sLen < 0 || sLen > len(sBuf) {
		return BAD_FUNC_ARG
	}
	if hashLen < 0 || hashLen > len(hash) {
		return BAD_FUNC_ARG
	}
	if res == nil || len(rBuf) == 0 || len(sBuf) == 0 || len(hash) == 0 {
		return BAD_FUNC_ARG
	}
	cRes := C.int(*res)
	ret := int(C.wc_ecc_verify_hash_ex_shim(
		(*C.uchar)(unsafe.Pointer(&rBuf[0])), C.word32(rLen),
		(*C.uchar)(unsafe.Pointer(&sBuf[0])), C.word32(sLen),
		(*C.uchar)(unsafe.Pointer(&hash[0])), C.word32(hashLen),
		&cRes, key,
	))
	*res = int(cRes)
	return ret
}

// Wc_ecc_rs_to_sig encodes hex-string R and S components into a DER signature.
// outLen must be set to the capacity of out before calling; it is updated to
// the actual encoded length on success.
func Wc_ecc_rs_to_sig(r, s string, out []byte, outLen *int) int {
	if outLen == nil || len(out) == 0 || *outLen < 0 || *outLen > len(out) {
		return BAD_FUNC_ARG
	}
	cR := C.CString(r)
	defer C.free(unsafe.Pointer(cR))
	cS := C.CString(s)
	defer C.free(unsafe.Pointer(cS))
	cOutLen := C.word32(*outLen)
	ret := int(C.wc_ecc_rs_to_sig_stub(cR, cS, (*C.uchar)(unsafe.Pointer(&out[0])), &cOutLen))
	*outLen = int(cOutLen)
	return ret
}

// Wc_ecc_sig_to_rs decodes a DER signature into raw big-endian R and S byte
// slices. rLen and sLen must be set to the capacity of r and s before calling;
// they are updated to the actual component lengths on success.
func Wc_ecc_sig_to_rs(sig []byte, sigLen int, r []byte, rLen *int, s []byte, sLen *int) int {
	if sigLen < 0 || sigLen > len(sig) {
		return BAD_FUNC_ARG
	}
	if rLen == nil || sLen == nil {
		return BAD_FUNC_ARG
	}
	if len(sig) == 0 || len(r) == 0 || len(s) == 0 {
		return BAD_FUNC_ARG
	}
	if *rLen < 0 || *rLen > len(r) || *sLen < 0 || *sLen > len(s) {
		return BAD_FUNC_ARG
	}
	cRLen := C.word32(*rLen)
	cSLen := C.word32(*sLen)
	ret := int(C.wc_ecc_sig_to_rs_stub(
		(*C.uchar)(unsafe.Pointer(&sig[0])), C.word32(sigLen),
		(*C.uchar)(unsafe.Pointer(&r[0])), &cRLen,
		(*C.uchar)(unsafe.Pointer(&s[0])), &cSLen,
	))
	*rLen = int(cRLen)
	*sLen = int(cSLen)
	return ret
}

// Wc_ecc_point_is_at_infinity returns 1 if the ECC point is the point at
// infinity, 0 if not, or a negative wolfSSL error code on failure.
func Wc_ecc_point_is_at_infinity(p *C.struct_ecc_point) int {
	return int(C.wc_ecc_point_is_at_infinity_stub(p))
}

// Wc_ecc_point_is_on_curve returns 0 if the point lies on the curve identified
// by curve_idx, or a negative wolfSSL error code if not (or on failure).
func Wc_ecc_point_is_on_curve(p *C.struct_ecc_point, curveIdx int) int {
	return int(C.wc_ecc_point_is_on_curve_stub(p, C.int(curveIdx)))
}

// Wc_ecc_get_curve_id returns the curve ID (ecc_curve_id) for a given curve
// table index, or a negative error code on failure.
func Wc_ecc_get_curve_id(curveIdx int) int {
	return int(C.wc_ecc_get_curve_id_stub(C.int(curveIdx)))
}

// Wc_ecc_get_curve_id_from_name returns the curve ID for the named curve
// (e.g. "SECP256R1"), or a negative error code if not found.
func Wc_ecc_get_curve_id_from_name(curveName string) int {
	cName := C.CString(curveName)
	defer C.free(unsafe.Pointer(cName))
	return int(C.wc_ecc_get_curve_id_from_name_stub(cName))
}

// Wc_ecc_get_curve_size_from_id returns the key size in bytes for the given
// curve ID, or a negative error code if the curve ID is unknown.
func Wc_ecc_get_curve_size_from_id(curveID int) int {
	return int(C.wc_ecc_get_curve_size_from_id_stub(C.int(curveID)))
}
