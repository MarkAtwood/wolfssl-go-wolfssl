/* base64.go
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
// #include <wolfssl/wolfcrypt/coding.h>
// #ifndef WOLFSSL_BASE64_ENCODE
// static int wc_go_Base64_Encode(const byte* in, word32 inLen,
//                                byte* out, word32* outLen) {
//     (void)in; (void)inLen; (void)out; (void)outLen; return -174;
// }
// static int wc_go_Base64_EncodeEsc(const byte* in, word32 inLen,
//                                    byte* out, word32* outLen) {
//     (void)in; (void)inLen; (void)out; (void)outLen; return -174;
// }
// static int wc_go_Base64_Encode_NoNl(const byte* in, word32 inLen,
//                                      byte* out, word32* outLen) {
//     (void)in; (void)inLen; (void)out; (void)outLen; return -174;
// }
// #else
// static int wc_go_Base64_Encode(const byte* in, word32 inLen,
//                                byte* out, word32* outLen) {
//     return Base64_Encode(in, inLen, out, outLen);
// }
// static int wc_go_Base64_EncodeEsc(const byte* in, word32 inLen,
//                                    byte* out, word32* outLen) {
//     return Base64_EncodeEsc(in, inLen, out, outLen);
// }
// static int wc_go_Base64_Encode_NoNl(const byte* in, word32 inLen,
//                                      byte* out, word32* outLen) {
//     return Base64_Encode_NoNl(in, inLen, out, outLen);
// }
// #endif
import "C"
import "unsafe"

// Base64_Decode decodes standard Base64 data from in into out.
// outLen must point to the capacity of out on entry; on success it is
// updated to the number of bytes written.
// Returns 0 on success, negative on error.
func Base64_Decode(in []byte, out []byte, outLen *int) int {
    if len(in) == 0 || len(out) == 0 || outLen == nil {
        return BAD_FUNC_ARG
    }
    cOutLen := C.word32(*outLen)
    ret := int(C.Base64_Decode(
        (*C.byte)(unsafe.Pointer(&in[0])), C.word32(len(in)),
        (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
    *outLen = int(cOutLen)
    return ret
}

// Base64_Encode encodes in into standard Base64 (with newlines) and
// writes to out.  outLen must point to the capacity of out on entry;
// on success it is updated to the number of bytes written.
// Returns 0 on success, negative on error.  Returns -174 when wolfSSL
// was built without WOLFSSL_BASE64_ENCODE.
func Base64_Encode(in []byte, out []byte, outLen *int) int {
    if len(in) == 0 || len(out) == 0 || outLen == nil {
        return BAD_FUNC_ARG
    }
    cOutLen := C.word32(*outLen)
    ret := int(C.wc_go_Base64_Encode(
        (*C.byte)(unsafe.Pointer(&in[0])), C.word32(len(in)),
        (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
    *outLen = int(cOutLen)
    return ret
}

// Base64_EncodeEsc encodes in into Base64 using escape-sequence line
// endings.  outLen must point to the capacity of out on entry; on
// success it is updated to the number of bytes written.
// Returns 0 on success, negative on error.  Returns -174 when wolfSSL
// was built without WOLFSSL_BASE64_ENCODE.
func Base64_EncodeEsc(in []byte, out []byte, outLen *int) int {
    if len(in) == 0 || len(out) == 0 || outLen == nil {
        return BAD_FUNC_ARG
    }
    cOutLen := C.word32(*outLen)
    ret := int(C.wc_go_Base64_EncodeEsc(
        (*C.byte)(unsafe.Pointer(&in[0])), C.word32(len(in)),
        (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
    *outLen = int(cOutLen)
    return ret
}

// Base64_Encode_NoNl encodes in into Base64 with no line endings.
// outLen must point to the capacity of out on entry; on success it is
// updated to the number of bytes written.
// Returns 0 on success, negative on error.  Returns -174 when wolfSSL
// was built without WOLFSSL_BASE64_ENCODE.
func Base64_Encode_NoNl(in []byte, out []byte, outLen *int) int {
    if len(in) == 0 || len(out) == 0 || outLen == nil {
        return BAD_FUNC_ARG
    }
    cOutLen := C.word32(*outLen)
    ret := int(C.wc_go_Base64_Encode_NoNl(
        (*C.byte)(unsafe.Pointer(&in[0])), C.word32(len(in)),
        (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
    *outLen = int(cOutLen)
    return ret
}
