// SPDX-FileCopyrightText: 2014 David Mzareulyan
// SPDX-License-Identifier: MIT
// Adapted from github.com/davidmz/go-pageant (v1.0.2), Copyright (c) 2014 David Mzareulyan.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package managementclient

import (
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	pageantMaxMessage  = 8192
	pageantCopyDataID  = 0x804e50ba
	pageantWMCopyData  = 74
	pageantAbortIfHung = 2
)

var (
	pageantMutex    sync.Mutex
	findWindow      = syscall.NewLazyDLL("user32.dll").NewProc("FindWindowW")
	sendWithTimeout = syscall.NewLazyDLL("user32.dll").NewProc("SendMessageTimeoutW")
	currentThread   = syscall.NewLazyDLL("kernel32.dll").NewProc("GetCurrentThreadId")
)

type pageantCopyData struct {
	data   uintptr
	length uint32
	buffer unsafe.Pointer
}

type pageantConnection struct {
	mutex sync.Mutex
	bytes []byte
}

func (this *pageantConnection) Write(request []byte) (int, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if len(this.bytes) != 0 {
		return 0, fmt.Errorf("unfinished Pageant response")
	}
	response, err := pageantQuery(request)
	if err != nil {
		return 0, err
	}
	this.bytes = response
	return len(request), nil
}

func (this *pageantConnection) Read(p []byte) (int, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if len(this.bytes) == 0 {
		return 0, io.EOF
	}
	n := copy(p, this.bytes)
	this.bytes = this.bytes[n:]
	return n, nil
}

func pageantWindow() uintptr {
	name, _ := syscall.UTF16PtrFromString("Pageant")
	window, _, _ := findWindow.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(name)))
	runtime.KeepAlive(name)
	return window
}

func pageantAvailable() bool { return pageantWindow() != 0 }

func pageantQuery(request []byte) ([]byte, error) {
	if len(request) < 4 || len(request) > pageantMaxMessage || int(binary.BigEndian.Uint32(request[:4])) != len(request)-4 {
		return nil, fmt.Errorf("invalid or oversized Pageant request")
	}
	pageantMutex.Lock()
	defer pageantMutex.Unlock()
	window := pageantWindow()
	if window == 0 {
		return nil, fmt.Errorf("Pageant is not running")
	}
	thread, _, _ := currentThread.Call()
	name := fmt.Sprintf("PageantRequest%08x", thread)
	mappedName, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	mapping, err := syscall.CreateFileMapping(syscall.InvalidHandle, nil, syscall.PAGE_READWRITE, 0, pageantMaxMessage, mappedName)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(mapping)
	pointer, err := syscall.MapViewOfFile(mapping, syscall.FILE_MAP_WRITE, 0, 0, pageantMaxMessage)
	if err != nil {
		return nil, err
	}
	defer syscall.UnmapViewOfFile(pointer)
	buffer := make([]byte, pageantMaxMessage)
	copy(buffer, request)
	var transferred uintptr
	if err := windows.WriteProcessMemory(windows.CurrentProcess(), pointer, &buffer[0], uintptr(len(buffer)), &transferred); err != nil || transferred != uintptr(len(buffer)) {
		return nil, fmt.Errorf("cannot write Pageant shared memory: %v", err)
	}
	nameBytes := append([]byte(name), 0)
	message := pageantCopyData{pageantCopyDataID, uint32(len(nameBytes)), unsafe.Pointer(&nameBytes[0])}
	var response uintptr
	status, _, sendErr := sendWithTimeout.Call(window, pageantWMCopyData, 0, uintptr(unsafe.Pointer(&message)), pageantAbortIfHung, 10_000, uintptr(unsafe.Pointer(&response)))
	runtime.KeepAlive(nameBytes)
	runtime.KeepAlive(message)
	if status == 0 || response == 0 {
		return nil, fmt.Errorf("Pageant did not respond within 10 seconds: %w", sendErr)
	}
	if err := windows.ReadProcessMemory(windows.CurrentProcess(), pointer, &buffer[0], uintptr(len(buffer)), &transferred); err != nil || transferred != uintptr(len(buffer)) {
		return nil, fmt.Errorf("cannot read Pageant shared memory: %v", err)
	}
	length := binary.BigEndian.Uint32(buffer[:4])
	if length > pageantMaxMessage-4 {
		return nil, fmt.Errorf("oversized Pageant response")
	}
	result := make([]byte, int(length)+4)
	copy(result, buffer[:len(result)])
	return result, nil
}
