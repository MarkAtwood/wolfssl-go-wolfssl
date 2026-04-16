/* tls_alpn_sni.go
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
// #include <wolfssl/ssl.h>
// #ifndef HAVE_ALPN
// int wolfSSL_UseALPN(WOLFSSL* ssl, char* protocol_name_list,
//                     unsigned int protocol_name_listSz,
//                     unsigned char options) {
//     (void)ssl; (void)protocol_name_list;
//     (void)protocol_name_listSz; (void)options;
//     return -174;
// }
// void wolfSSL_get0_alpn_selected(const WOLFSSL* ssl,
//                                 const unsigned char** data,
//                                 unsigned int* len) {
//     (void)ssl;
//     if (data) *data = 0;
//     if (len)  *len  = 0;
// }
// #endif /* HAVE_ALPN */
// #ifndef HAVE_SNI
// int wolfSSL_UseSNI(WOLFSSL* ssl, unsigned char type,
//                    const void* data, unsigned short size) {
//     (void)ssl; (void)type; (void)data; (void)size;
//     return -174;
// }
// int wolfSSL_CTX_UseSNI(WOLFSSL_CTX* ctx, unsigned char type,
//                         const void* data, unsigned short size) {
//     (void)ctx; (void)type; (void)data; (void)size;
//     return -174;
// }
// unsigned char wolfSSL_SNI_Status(WOLFSSL* ssl, unsigned char type) {
//     (void)ssl; (void)type;
//     return 0;
// }
// unsigned short wolfSSL_SNI_GetRequest(WOLFSSL* ssl, unsigned char type,
//                                       void** data) {
//     (void)ssl; (void)type;
//     if (data) *data = 0;
//     return 0;
// }
// void wolfSSL_CTX_set_servername_callback(WOLFSSL_CTX* ctx, void* cb) {
//     (void)ctx; (void)cb;
// }
// #endif /* HAVE_SNI */
import "C"
import (
	"unsafe"
)

// WolfSSL_UseALPN sets the ALPN protocol list on a WOLFSSL session.
// protocol_name_list is a comma-separated list of protocol names.
// Returns WOLFSSL_SUCCESS on success or a negative error code.
func WolfSSL_UseALPN(ssl *C.struct_WOLFSSL, protocolNameList string, options int) int {
	if options < 0 || options > 0xFF {
		return BAD_FUNC_ARG
	}
	cList := C.CString(protocolNameList)
	defer C.free(unsafe.Pointer(cList))
	return int(C.wolfSSL_UseALPN(ssl, cList,
		C.uint(len(protocolNameList)), C.uchar(options)))
}

// WolfSSL_get0_alpn_selected retrieves the negotiated ALPN protocol after the
// handshake.  The returned slice references wolfSSL-internal memory and must
// not be freed or modified by the caller.
func WolfSSL_get0_alpn_selected(ssl *C.struct_WOLFSSL) []byte {
	var data *C.uchar
	var length C.uint
	C.wolfSSL_get0_alpn_selected(ssl, &data, &length)
	if data == nil || length == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(data), C.int(length))
}

// WolfSSL_UseSNI adds a Server Name Indication extension to a WOLFSSL session.
// type_ should be WOLFSSL_SNI_HOST_NAME (0).
// Returns WOLFSSL_SUCCESS on success or a negative error code.
func WolfSSL_UseSNI(ssl *C.struct_WOLFSSL, type_ int, hostname string) int {
	cHost := C.CString(hostname)
	defer C.free(unsafe.Pointer(cHost))
	return int(C.wolfSSL_UseSNI(ssl, C.uchar(type_),
		unsafe.Pointer(cHost), C.ushort(len(hostname))))
}

// WolfSSL_CTX_UseSNI adds a Server Name Indication extension to all WOLFSSL
// sessions created from ctx.
// Returns WOLFSSL_SUCCESS on success or a negative error code.
func WolfSSL_CTX_UseSNI(ctx *C.struct_WOLFSSL_CTX, type_ int, hostname string) int {
	cHost := C.CString(hostname)
	defer C.free(unsafe.Pointer(cHost))
	return int(C.wolfSSL_CTX_UseSNI(ctx, C.uchar(type_),
		unsafe.Pointer(cHost), C.ushort(len(hostname))))
}

// WolfSSL_SNI_Status returns the SNI match status for the given SNI type after
// the handshake.
func WolfSSL_SNI_Status(ssl *C.struct_WOLFSSL, type_ int) int {
	return int(C.wolfSSL_SNI_Status(ssl, C.uchar(type_)))
}

// WolfSSL_SNI_GetRequest returns the SNI hostname sent by the client.  The
// data pointer is set to wolfSSL-internal memory; the caller must not free it.
// Returns the length of the SNI data in bytes.
func WolfSSL_SNI_GetRequest(ssl *C.struct_WOLFSSL, type_ int) ([]byte, int) {
	var data unsafe.Pointer
	length := int(C.wolfSSL_SNI_GetRequest(ssl, C.uchar(type_), &data))
	if data == nil || length == 0 {
		return nil, 0
	}
	return C.GoBytes(data, C.int(length)), length
}

// WolfSSL_CTX_set_servername_callback sets the SNI received callback on ctx.
// cb must be a C function pointer of type CallbackSniRecv cast to unsafe.Pointer,
// or nil to clear the callback.
func WolfSSL_CTX_set_servername_callback(ctx *C.struct_WOLFSSL_CTX, cb unsafe.Pointer) {
	C.wolfSSL_CTX_set_servername_callback(ctx, (*[0]byte)(cb))
}

// WolfSSL_set_tlsext_host_name sets the SNI hostname on a WOLFSSL session.
// This is equivalent to WolfSSL_UseSNI with type WOLFSSL_SNI_HOST_NAME.
// Returns WOLFSSL_SUCCESS on success or a negative error code.
func WolfSSL_set_tlsext_host_name(ssl *C.struct_WOLFSSL, hostname string) int {
	cHost := C.CString(hostname)
	defer C.free(unsafe.Pointer(cHost))
	return int(C.wolfSSL_set_tlsext_host_name(ssl, cHost))
}
