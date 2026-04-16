/* async.go
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
// #include <wolfssl/wolfcrypt/types.h>
// #ifdef WOLFSSL_ASYNC_CRYPT
// #include <wolfssl/wolfcrypt/async.h>
// #include <wolfssl/wolfcrypt/wolfevent.h>
// #else
// typedef struct WC_ASYNC_DEV {} WC_ASYNC_DEV;
// static int wolfAsync_DevOpen(int *devId) {
//     (void)devId;
//     return -174;
// }
// static void wolfAsync_DevClose(int *devId) {
//     (void)devId;
// }
// static int wolfAsync_DevCtxInit(WC_ASYNC_DEV* asyncDev, unsigned int marker,
//         void* heap, int devId) {
//     (void)asyncDev; (void)marker; (void)heap; (void)devId;
//     return -174;
// }
// static void wolfAsync_DevCtxFree(WC_ASYNC_DEV* asyncDev, unsigned int marker) {
//     (void)asyncDev; (void)marker;
// }
// typedef struct WOLF_EVENT {} WOLF_EVENT;
// typedef struct WOLF_EVENT_QUEUE {} WOLF_EVENT_QUEUE;
// static int wc_AsyncWait(int ret, WC_ASYNC_DEV* asyncDev, unsigned int flags) {
//     (void)asyncDev; (void)flags;
//     return ret;
// }
// static int wc_AsyncHandle(WC_ASYNC_DEV* asyncDev, WOLF_EVENT_QUEUE* queue,
//         unsigned int flags) {
//     (void)asyncDev; (void)queue; (void)flags;
//     return -174;
// }
// #endif
import "C"
import "unsafe"

// WolfAsync_DevOpen opens an async hardware device and returns its device ID.
// Returns 0 on success, negative on error.
// Always returns -174 (NOT_COMPILED_IN) when WOLFSSL_ASYNC_CRYPT is not enabled.
func WolfAsync_DevOpen(devId *int) int {
	var cDevId C.int
	ret := int(C.wolfAsync_DevOpen(&cDevId))
	*devId = int(cDevId)
	return ret
}

// WolfAsync_DevClose closes the async hardware device identified by devId.
func WolfAsync_DevClose(devId *int) {
	cDevId := C.int(*devId)
	C.wolfAsync_DevClose(&cDevId)
	*devId = int(cDevId)
}

// WolfAsync_DevCtxInit initializes a WC_ASYNC_DEV context with the given
// marker, heap pointer, and device ID.
// heap must be a *WOLFSSL_HEAP_HINT obtained from Wc_LoadStaticMemory, or nil
// to use the default system allocator. wolfSSL stores this pointer for the
// lifetime of the context; passing a Go heap pointer here is not supported.
// Returns 0 on success, negative on error.
func WolfAsync_DevCtxInit(asyncDev *C.struct_WC_ASYNC_DEV, marker uint, heap *C.struct_WOLFSSL_HEAP_HINT, devId int) int {
	return int(C.wolfAsync_DevCtxInit(asyncDev, C.word32(marker), unsafe.Pointer(heap), C.int(devId)))
}

// WolfAsync_DevCtxFree frees a WC_ASYNC_DEV context.
func WolfAsync_DevCtxFree(asyncDev *C.struct_WC_ASYNC_DEV, marker uint) {
	C.wolfAsync_DevCtxFree(asyncDev, C.word32(marker))
}

// Wc_AsyncWait waits for an async operation to complete.
// Pass the return code from the initiating call as ret.
// Returns 0 when complete, WC_PENDING_E if still pending, negative on error.
func Wc_AsyncWait(ret int, asyncDev *C.struct_WC_ASYNC_DEV, flags uint) int {
	return int(C.wc_AsyncWait(C.int(ret), asyncDev, C.word32(flags)))
}

// Wc_AsyncHandle pushes an async operation onto an event queue.
// Returns 0 on success, negative on error.
func Wc_AsyncHandle(asyncDev *C.struct_WC_ASYNC_DEV, queue *C.struct_WOLF_EVENT_QUEUE, flags uint) int {
	return int(C.wc_AsyncHandle(asyncDev, queue, C.word32(flags)))
}
