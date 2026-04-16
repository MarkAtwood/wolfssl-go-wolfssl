/* aes_modes.go
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
//
// /* AES-ECB stubs */
// #ifndef HAVE_AES_ECB
// static int wc_AesEcbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//     (void)aes; (void)out; (void)in; (void)sz; return -174;
// }
// static int wc_AesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//     (void)aes; (void)out; (void)in; (void)sz; return -174;
// }
// #endif /* !HAVE_AES_ECB */
//
// /* AES-OFB stubs */
// #ifndef WOLFSSL_AES_OFB
// static int wc_AesOfbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//     (void)aes; (void)out; (void)in; (void)sz; return -174;
// }
// static int wc_AesOfbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//     (void)aes; (void)out; (void)in; (void)sz; return -174;
// }
// #elif !defined(HAVE_AES_DECRYPT)
// static int wc_AesOfbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//     (void)aes; (void)out; (void)in; (void)sz; return -174;
// }
// #endif /* !WOLFSSL_AES_OFB / !HAVE_AES_DECRYPT */
//
// /* AES-CFB stubs */
// #ifndef WOLFSSL_AES_CFB
// static int wc_AesCfbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//     (void)aes; (void)out; (void)in; (void)sz; return -174;
// }
// static int wc_AesCfb1Encrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//     (void)aes; (void)out; (void)in; (void)sz; return -174;
// }
// static int wc_AesCfb8Encrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//     (void)aes; (void)out; (void)in; (void)sz; return -174;
// }
// static int wc_AesCfbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//     (void)aes; (void)out; (void)in; (void)sz; return -174;
// }
// static int wc_AesCfb1Decrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//     (void)aes; (void)out; (void)in; (void)sz; return -174;
// }
// static int wc_AesCfb8Decrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//     (void)aes; (void)out; (void)in; (void)sz; return -174;
// }
// #elif !defined(HAVE_AES_DECRYPT)
// static int wc_AesCfbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//     (void)aes; (void)out; (void)in; (void)sz; return -174;
// }
// static int wc_AesCfb1Decrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//     (void)aes; (void)out; (void)in; (void)sz; return -174;
// }
// static int wc_AesCfb8Decrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
//     (void)aes; (void)out; (void)in; (void)sz; return -174;
// }
// #endif /* !WOLFSSL_AES_CFB / !HAVE_AES_DECRYPT */
//
// /* AES-XTS stubs */
// #ifndef WOLFSSL_AES_XTS
// typedef struct { int dummy; } XtsAes;
// static int wc_AesXtsInit(XtsAes* aes, void* heap, int devId) {
//     (void)aes; (void)heap; (void)devId; return -174;
// }
// static int wc_AesXtsSetKeyNoInit(XtsAes* aes, const byte* key, word32 len, int dir) {
//     (void)aes; (void)key; (void)len; (void)dir; return -174;
// }
// static int wc_AesXtsSetKey(XtsAes* aes, const byte* key, word32 len, int dir,
//                            void* heap, int devId) {
//     (void)aes; (void)key; (void)len; (void)dir; (void)heap; (void)devId; return -174;
// }
// static int wc_AesXtsEncrypt(XtsAes* aes, byte* out, const byte* in, word32 sz,
//                             const byte* i, word32 iSz) {
//     (void)aes; (void)out; (void)in; (void)sz; (void)i; (void)iSz; return -174;
// }
// static int wc_AesXtsDecrypt(XtsAes* aes, byte* out, const byte* in, word32 sz,
//                             const byte* i, word32 iSz) {
//     (void)aes; (void)out; (void)in; (void)sz; (void)i; (void)iSz; return -174;
// }
// static int wc_AesXtsFree(XtsAes* aes) {
//     (void)aes; return -174;
// }
// #endif /* !WOLFSSL_AES_XTS */
//
// /* AES-GCM streaming stubs */
// #if !defined(HAVE_AESGCM)
// static int wc_AesGcmSetExtIV(Aes* aes, const byte* iv, word32 ivSz) {
//     (void)aes; (void)iv; (void)ivSz; return -174;
// }
// #elif defined(WC_NO_RNG)
// static int wc_AesGcmSetExtIV(Aes* aes, const byte* iv, word32 ivSz) {
//     (void)aes; (void)iv; (void)ivSz; return -174;
// }
// #endif /* !HAVE_AESGCM || WC_NO_RNG */
//
// #if !defined(HAVE_AESGCM) || !defined(WOLFSSL_AESGCM_STREAM)
// static int wc_AesGcmEncryptInit(Aes* aes, const byte* key, word32 len,
//                                 const byte* iv, word32 ivSz) {
//     (void)aes; (void)key; (void)len; (void)iv; (void)ivSz; return -174;
// }
// static int wc_AesGcmEncryptUpdate(Aes* aes, byte* out, const byte* in,
//                                   word32 sz, const byte* authIn, word32 authInSz) {
//     (void)aes; (void)out; (void)in; (void)sz; (void)authIn; (void)authInSz; return -174;
// }
// static int wc_AesGcmEncryptFinal(Aes* aes, byte* authTag, word32 authTagSz) {
//     (void)aes; (void)authTag; (void)authTagSz; return -174;
// }
// static int wc_AesGcmDecryptInit(Aes* aes, const byte* key, word32 len,
//                                 const byte* iv, word32 ivSz) {
//     (void)aes; (void)key; (void)len; (void)iv; (void)ivSz; return -174;
// }
// static int wc_AesGcmDecryptUpdate(Aes* aes, byte* out, const byte* in,
//                                   word32 sz, const byte* authIn, word32 authInSz) {
//     (void)aes; (void)out; (void)in; (void)sz; (void)authIn; (void)authInSz; return -174;
// }
// static int wc_AesGcmDecryptFinal(Aes* aes, const byte* authTag, word32 authTagSz) {
//     (void)aes; (void)authTag; (void)authTagSz; return -174;
// }
// #endif /* !HAVE_AESGCM || !WOLFSSL_AESGCM_STREAM */
import "C"
import (
    "unsafe"
)

// AesXts is the XTS-mode AES context struct.
type AesXts = C.XtsAes

// ---------------------------------------------------------------------------
// AES-ECB (guard: HAVE_AES_ECB)
// ---------------------------------------------------------------------------

// Wc_AesEcbEncrypt encrypts sz bytes of in into out using AES-ECB.
// sz must be a positive multiple of AES_BLOCK_SIZE.
// The Aes struct must already be initialised with wc_AesSetKey (AES_ENCRYPTION).
func Wc_AesEcbEncrypt(aes *C.struct_Aes, out []byte, in []byte, sz int) int {
    if sz <= 0 || sz > len(in) || sz > len(out) {
        return BAD_FUNC_ARG
    }
    if sz%AES_BLOCK_SIZE != 0 {
        return BAD_FUNC_ARG
    }
    return int(C.wc_AesEcbEncrypt(aes,
        (*C.uchar)(unsafe.Pointer(&out[0])),
        (*C.uchar)(unsafe.Pointer(&in[0])),
        C.word32(sz)))
}

// Wc_AesEcbDecrypt decrypts sz bytes of in into out using AES-ECB.
// sz must be a positive multiple of AES_BLOCK_SIZE.
// The Aes struct must already be initialised with wc_AesSetKey (AES_DECRYPTION).
func Wc_AesEcbDecrypt(aes *C.struct_Aes, out []byte, in []byte, sz int) int {
    if sz <= 0 || sz > len(in) || sz > len(out) {
        return BAD_FUNC_ARG
    }
    if sz%AES_BLOCK_SIZE != 0 {
        return BAD_FUNC_ARG
    }
    return int(C.wc_AesEcbDecrypt(aes,
        (*C.uchar)(unsafe.Pointer(&out[0])),
        (*C.uchar)(unsafe.Pointer(&in[0])),
        C.word32(sz)))
}

// ---------------------------------------------------------------------------
// AES-OFB (guard: WOLFSSL_AES_OFB)
// ---------------------------------------------------------------------------

// Wc_AesOfbEncrypt encrypts sz bytes of in into out using AES-OFB.
// The Aes struct must already be initialised with wc_AesSetKey (AES_ENCRYPTION).
func Wc_AesOfbEncrypt(aes *C.struct_Aes, out []byte, in []byte, sz int) int {
    if sz < 0 || sz > len(in) || sz > len(out) {
        return BAD_FUNC_ARG
    }
    if sz == 0 {
        return 0
    }
    return int(C.wc_AesOfbEncrypt(aes,
        (*C.uchar)(unsafe.Pointer(&out[0])),
        (*C.uchar)(unsafe.Pointer(&in[0])),
        C.word32(sz)))
}

// Wc_AesOfbDecrypt decrypts sz bytes of in into out using AES-OFB.
// The Aes struct must already be initialised with wc_AesSetKey (AES_ENCRYPTION).
func Wc_AesOfbDecrypt(aes *C.struct_Aes, out []byte, in []byte, sz int) int {
    if sz < 0 || sz > len(in) || sz > len(out) {
        return BAD_FUNC_ARG
    }
    if sz == 0 {
        return 0
    }
    return int(C.wc_AesOfbDecrypt(aes,
        (*C.uchar)(unsafe.Pointer(&out[0])),
        (*C.uchar)(unsafe.Pointer(&in[0])),
        C.word32(sz)))
}

// ---------------------------------------------------------------------------
// AES-CFB (guard: WOLFSSL_AES_CFB)
// ---------------------------------------------------------------------------

// Wc_AesCfbEncrypt encrypts sz bytes of in into out using AES-CFB128.
// The Aes struct must already be initialised with wc_AesSetKey (AES_ENCRYPTION).
func Wc_AesCfbEncrypt(aes *C.struct_Aes, out []byte, in []byte, sz int) int {
    if sz < 0 || sz > len(in) || sz > len(out) {
        return BAD_FUNC_ARG
    }
    if sz == 0 {
        return 0
    }
    return int(C.wc_AesCfbEncrypt(aes,
        (*C.uchar)(unsafe.Pointer(&out[0])),
        (*C.uchar)(unsafe.Pointer(&in[0])),
        C.word32(sz)))
}

// Wc_AesCfbDecrypt decrypts sz bytes of in into out using AES-CFB128.
// The Aes struct must already be initialised with wc_AesSetKey (AES_ENCRYPTION).
func Wc_AesCfbDecrypt(aes *C.struct_Aes, out []byte, in []byte, sz int) int {
    if sz < 0 || sz > len(in) || sz > len(out) {
        return BAD_FUNC_ARG
    }
    if sz == 0 {
        return 0
    }
    return int(C.wc_AesCfbDecrypt(aes,
        (*C.uchar)(unsafe.Pointer(&out[0])),
        (*C.uchar)(unsafe.Pointer(&in[0])),
        C.word32(sz)))
}

// Wc_AesCfb1Encrypt encrypts sz bits of in into out using AES-CFB1.
// sz is measured in bits. The Aes struct must already be initialised with
// wc_AesSetKey (AES_ENCRYPTION).
func Wc_AesCfb1Encrypt(aes *C.struct_Aes, out []byte, in []byte, sz int) int {
    if sz < 0 {
        return BAD_FUNC_ARG
    }
    if sz == 0 {
        return 0
    }
    bytesNeeded := (sz + 7) / 8
    if bytesNeeded > len(in) || bytesNeeded > len(out) {
        return BAD_FUNC_ARG
    }
    return int(C.wc_AesCfb1Encrypt(aes,
        (*C.uchar)(unsafe.Pointer(&out[0])),
        (*C.uchar)(unsafe.Pointer(&in[0])),
        C.word32(sz)))
}

// Wc_AesCfb1Decrypt decrypts sz bits of in into out using AES-CFB1.
// sz is measured in bits. The Aes struct must already be initialised with
// wc_AesSetKey (AES_ENCRYPTION).
func Wc_AesCfb1Decrypt(aes *C.struct_Aes, out []byte, in []byte, sz int) int {
    if sz < 0 {
        return BAD_FUNC_ARG
    }
    if sz == 0 {
        return 0
    }
    bytesNeeded := (sz + 7) / 8
    if bytesNeeded > len(in) || bytesNeeded > len(out) {
        return BAD_FUNC_ARG
    }
    return int(C.wc_AesCfb1Decrypt(aes,
        (*C.uchar)(unsafe.Pointer(&out[0])),
        (*C.uchar)(unsafe.Pointer(&in[0])),
        C.word32(sz)))
}

// Wc_AesCfb8Encrypt encrypts sz bytes of in into out using AES-CFB8.
// The Aes struct must already be initialised with wc_AesSetKey (AES_ENCRYPTION).
func Wc_AesCfb8Encrypt(aes *C.struct_Aes, out []byte, in []byte, sz int) int {
    if sz < 0 || sz > len(in) || sz > len(out) {
        return BAD_FUNC_ARG
    }
    if sz == 0 {
        return 0
    }
    return int(C.wc_AesCfb8Encrypt(aes,
        (*C.uchar)(unsafe.Pointer(&out[0])),
        (*C.uchar)(unsafe.Pointer(&in[0])),
        C.word32(sz)))
}

// Wc_AesCfb8Decrypt decrypts sz bytes of in into out using AES-CFB8.
// The Aes struct must already be initialised with wc_AesSetKey (AES_ENCRYPTION).
func Wc_AesCfb8Decrypt(aes *C.struct_Aes, out []byte, in []byte, sz int) int {
    if sz < 0 || sz > len(in) || sz > len(out) {
        return BAD_FUNC_ARG
    }
    if sz == 0 {
        return 0
    }
    return int(C.wc_AesCfb8Decrypt(aes,
        (*C.uchar)(unsafe.Pointer(&out[0])),
        (*C.uchar)(unsafe.Pointer(&in[0])),
        C.word32(sz)))
}

// ---------------------------------------------------------------------------
// AES-XTS (guard: WOLFSSL_AES_XTS)
// ---------------------------------------------------------------------------

// Wc_AesXtsInit initialises an XtsAes context.
// devId should be INVALID_DEVID unless using a hardware device.
func Wc_AesXtsInit(aes *C.XtsAes, devId int) int {
    return int(C.wc_AesXtsInit(aes, unsafe.Pointer(nil), C.int(devId)))
}

// Wc_AesXtsSetKeyNoInit sets the key on an already-initialised XtsAes context
// without re-initialising the struct. dir must be AES_ENCRYPTION or AES_DECRYPTION.
// key must be twice the desired AES key size (the XTS key is a concatenation of
// two equal-length AES keys).
func Wc_AesXtsSetKeyNoInit(aes *C.XtsAes, key []byte, length int, dir int) int {
    if length <= 0 || length > len(key) {
        return BAD_FUNC_ARG
    }
    return int(C.wc_AesXtsSetKeyNoInit(aes,
        (*C.uchar)(unsafe.Pointer(&key[0])),
        C.word32(length),
        C.int(dir)))
}

// Wc_AesXtsSetKey initialises an XtsAes context and sets the key in one call.
// dir must be AES_ENCRYPTION or AES_DECRYPTION.
// key must be twice the desired AES key size.
func Wc_AesXtsSetKey(aes *C.XtsAes, key []byte, length int, dir int, devId int) int {
    if length <= 0 || length > len(key) {
        return BAD_FUNC_ARG
    }
    return int(C.wc_AesXtsSetKey(aes,
        (*C.uchar)(unsafe.Pointer(&key[0])),
        C.word32(length),
        C.int(dir),
        unsafe.Pointer(nil),
        C.int(devId)))
}

// Wc_AesXtsEncrypt encrypts sz bytes of in into out using AES-XTS.
// tweak is the sector-level tweak (data unit identifier), iSz bytes long.
// iSz is typically AES_BLOCK_SIZE (16 bytes).
func Wc_AesXtsEncrypt(aes *C.XtsAes, out []byte, in []byte, sz int, tweak []byte, iSz int) int {
    if sz <= 0 || sz > len(in) || sz > len(out) {
        return BAD_FUNC_ARG
    }
    if iSz <= 0 || iSz > len(tweak) {
        return BAD_FUNC_ARG
    }
    return int(C.wc_AesXtsEncrypt(aes,
        (*C.uchar)(unsafe.Pointer(&out[0])),
        (*C.uchar)(unsafe.Pointer(&in[0])),
        C.word32(sz),
        (*C.uchar)(unsafe.Pointer(&tweak[0])),
        C.word32(iSz)))
}

// Wc_AesXtsDecrypt decrypts sz bytes of in into out using AES-XTS.
// tweak is the sector-level tweak (data unit identifier), iSz bytes long.
// iSz is typically AES_BLOCK_SIZE (16 bytes).
func Wc_AesXtsDecrypt(aes *C.XtsAes, out []byte, in []byte, sz int, tweak []byte, iSz int) int {
    if sz <= 0 || sz > len(in) || sz > len(out) {
        return BAD_FUNC_ARG
    }
    if iSz <= 0 || iSz > len(tweak) {
        return BAD_FUNC_ARG
    }
    return int(C.wc_AesXtsDecrypt(aes,
        (*C.uchar)(unsafe.Pointer(&out[0])),
        (*C.uchar)(unsafe.Pointer(&in[0])),
        C.word32(sz),
        (*C.uchar)(unsafe.Pointer(&tweak[0])),
        C.word32(iSz)))
}

// Wc_AesXtsFree releases resources associated with an XtsAes context.
func Wc_AesXtsFree(aes *C.XtsAes) int {
    return int(C.wc_AesXtsFree(aes))
}

// ---------------------------------------------------------------------------
// AES-GCM streaming (guard: HAVE_AESGCM && WOLFSSL_AESGCM_STREAM)
// ---------------------------------------------------------------------------

// Wc_AesGcmSetExtIV sets a fixed external IV on an Aes context that was
// previously keyed with Wc_AesGcmSetKey. Requires HAVE_AESGCM and a build
// without WC_NO_RNG.
func Wc_AesGcmSetExtIV(aes *C.struct_Aes, iv []byte, ivSz int) int {
    if ivSz <= 0 || ivSz > len(iv) {
        return BAD_FUNC_ARG
    }
    return int(C.wc_AesGcmSetExtIV(aes,
        (*C.uchar)(unsafe.Pointer(&iv[0])),
        C.word32(ivSz)))
}

// Wc_AesGcmEncryptInit initialises a streaming AES-GCM encrypt operation.
// key may be nil if the key was already set via Wc_AesGcmSetKey; if non-nil,
// length must be a valid AES key size.
// iv may be nil if the IV was already set; if non-nil, ivSz must be > 0.
func Wc_AesGcmEncryptInit(aes *C.struct_Aes, key []byte, length int, iv []byte, ivSz int) int {
    var keyPtr *C.uchar
    if len(key) > 0 {
        if length <= 0 || length > len(key) {
            return BAD_FUNC_ARG
        }
        keyPtr = (*C.uchar)(unsafe.Pointer(&key[0]))
    }
    var ivPtr *C.uchar
    if len(iv) > 0 {
        if ivSz <= 0 || ivSz > len(iv) {
            return BAD_FUNC_ARG
        }
        ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
    }
    return int(C.wc_AesGcmEncryptInit(aes, keyPtr, C.word32(length), ivPtr, C.word32(ivSz)))
}

// Wc_AesGcmEncryptUpdate feeds plaintext and/or additional authenticated data
// into an in-progress AES-GCM encrypt stream. Either in or authIn may be empty.
func Wc_AesGcmEncryptUpdate(aes *C.struct_Aes, out []byte, in []byte, authIn []byte) int {
    sz := len(in)
    if sz > len(out) {
        return BAD_FUNC_ARG
    }
    var outPtr *C.uchar
    if sz > 0 {
        outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
    }
    var inPtr *C.uchar
    if sz > 0 {
        inPtr = (*C.uchar)(unsafe.Pointer(&in[0]))
    }
    var authInPtr *C.uchar
    if len(authIn) > 0 {
        authInPtr = (*C.uchar)(unsafe.Pointer(&authIn[0]))
    }
    return int(C.wc_AesGcmEncryptUpdate(aes, outPtr, inPtr, C.word32(sz),
        authInPtr, C.word32(len(authIn))))
}

// Wc_AesGcmEncryptFinal finalises a streaming AES-GCM encrypt and writes the
// authentication tag into authTag. len(authTag) must be > 0.
func Wc_AesGcmEncryptFinal(aes *C.struct_Aes, authTag []byte) int {
    if len(authTag) == 0 {
        return BAD_FUNC_ARG
    }
    return int(C.wc_AesGcmEncryptFinal(aes,
        (*C.uchar)(unsafe.Pointer(&authTag[0])),
        C.word32(len(authTag))))
}

// Wc_AesGcmDecryptInit initialises a streaming AES-GCM decrypt operation.
// key and iv follow the same nil-signalling convention as Wc_AesGcmEncryptInit.
func Wc_AesGcmDecryptInit(aes *C.struct_Aes, key []byte, length int, iv []byte, ivSz int) int {
    var keyPtr *C.uchar
    if len(key) > 0 {
        if length <= 0 || length > len(key) {
            return BAD_FUNC_ARG
        }
        keyPtr = (*C.uchar)(unsafe.Pointer(&key[0]))
    }
    var ivPtr *C.uchar
    if len(iv) > 0 {
        if ivSz <= 0 || ivSz > len(iv) {
            return BAD_FUNC_ARG
        }
        ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
    }
    return int(C.wc_AesGcmDecryptInit(aes, keyPtr, C.word32(length), ivPtr, C.word32(ivSz)))
}

// Wc_AesGcmDecryptUpdate feeds ciphertext and/or additional authenticated data
// into an in-progress AES-GCM decrypt stream. Either in or authIn may be empty.
func Wc_AesGcmDecryptUpdate(aes *C.struct_Aes, out []byte, in []byte, authIn []byte) int {
    sz := len(in)
    if sz > len(out) {
        return BAD_FUNC_ARG
    }
    var outPtr *C.uchar
    if sz > 0 {
        outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
    }
    var inPtr *C.uchar
    if sz > 0 {
        inPtr = (*C.uchar)(unsafe.Pointer(&in[0]))
    }
    var authInPtr *C.uchar
    if len(authIn) > 0 {
        authInPtr = (*C.uchar)(unsafe.Pointer(&authIn[0]))
    }
    return int(C.wc_AesGcmDecryptUpdate(aes, outPtr, inPtr, C.word32(sz),
        authInPtr, C.word32(len(authIn))))
}

// Wc_AesGcmDecryptFinal finalises a streaming AES-GCM decrypt and verifies the
// authentication tag. Returns 0 on success, negative on tag mismatch or error.
func Wc_AesGcmDecryptFinal(aes *C.struct_Aes, authTag []byte) int {
    if len(authTag) == 0 {
        return BAD_FUNC_ARG
    }
    return int(C.wc_AesGcmDecryptFinal(aes,
        (*C.uchar)(unsafe.Pointer(&authTag[0])),
        C.word32(len(authTag))))
}
