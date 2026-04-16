/* static_mem.go
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
// #include <wolfssl/wolfcrypt/memory.h>
// #ifndef WOLFSSL_STATIC_MEMORY
// static int wolfSSL_CTX_load_static_memory(WOLFSSL_CTX** ctx,
//         wolfSSL_method_func method,
//         unsigned char* buf, unsigned int sz,
//         int flag, int max) {
//     (void)ctx; (void)method; (void)buf; (void)sz; (void)flag; (void)max;
//     return -174;
// }
// static int wolfSSL_CTX_is_static_memory(WOLFSSL_CTX* ctx,
//         void* mem_stats) {
//     (void)ctx; (void)mem_stats;
//     return -174;
// }
// typedef struct WOLFSSL_HEAP_HINT {} WOLFSSL_HEAP_HINT;
// static int wc_LoadStaticMemory(WOLFSSL_HEAP_HINT** pHint,
//         unsigned char* buf, unsigned int sz, int flag, int max) {
//     (void)pHint; (void)buf; (void)sz; (void)flag; (void)max;
//     return -174;
// }
// static void wc_UnloadStaticMemory(WOLFSSL_HEAP_HINT* heap) {
//     (void)heap;
// }
// #endif
import "C"
import "unsafe"

// Static memory pool flag constants (WOLFSSL_STATIC_MEMORY).
const (
	WOLFMEM_GENERAL       = 0x01
	WOLFMEM_IO_POOL       = 0x02
	WOLFMEM_IO_POOL_FIXED = 0x04
	WOLFMEM_TRACK_STATS   = 0x08
)

// WolfSSL_CTX_load_static_memory initializes or attaches a WOLFSSL_CTX to a
// caller-supplied static memory buffer.  Pass method=nil to use an existing
// ctx, or a non-nil method to allocate a new ctx from the buffer.
// buf must remain valid for the lifetime of the context.
// Returns WOLFSSL_SUCCESS on success, negative on error.
// Always returns -174 (NOT_COMPILED_IN) when WOLFSSL_STATIC_MEMORY is not enabled.
func WolfSSL_CTX_load_static_memory(ctx **C.struct_WOLFSSL_CTX, buf []byte, flag int, max int) int {
	if len(buf) == 0 {
		return -174
	}
	return int(C.wolfSSL_CTX_load_static_memory(
		ctx,
		nil,
		(*C.uchar)(unsafe.Pointer(&buf[0])),
		C.uint(len(buf)),
		C.int(flag),
		C.int(max),
	))
}

// WolfSSL_CTX_is_static_memory returns non-zero when ctx was created with a
// static memory pool.  When WOLFSSL_STATIC_MEMORY is enabled, mem_stats may be
// non-nil and will be populated with current usage statistics.
// Returns -174 (NOT_COMPILED_IN) when the feature is disabled.
func WolfSSL_CTX_is_static_memory(ctx *C.struct_WOLFSSL_CTX) int {
	return int(C.wolfSSL_CTX_is_static_memory(ctx, nil))
}

// Wc_LoadStaticMemory initializes a WOLFSSL_HEAP_HINT from a static buffer for
// use by wolfcrypt (non-TLS) operations.
// buf must remain valid for the lifetime of the hint.
// Returns 0 on success, negative on error.
func Wc_LoadStaticMemory(buf []byte, flag int, max int) (*C.struct_WOLFSSL_HEAP_HINT, int) {
	if len(buf) == 0 {
		return nil, -174
	}
	var hint *C.struct_WOLFSSL_HEAP_HINT
	ret := int(C.wc_LoadStaticMemory(
		&hint,
		(*C.uchar)(unsafe.Pointer(&buf[0])),
		C.uint(len(buf)),
		C.int(flag),
		C.int(max),
	))
	return hint, ret
}

// Wc_UnloadStaticMemory releases a WOLFSSL_HEAP_HINT previously obtained from
// Wc_LoadStaticMemory.
func Wc_UnloadStaticMemory(hint *C.struct_WOLFSSL_HEAP_HINT) {
	C.wc_UnloadStaticMemory(hint)
}
