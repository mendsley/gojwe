// Copyright 2014 Matthew Endsley
// All rights reserved
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted providing that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package gojwe

import (
	"bytes"
	"testing"
)

// A.1.8 - JSON Web Encryption
func TestAESKeyWrap(t *testing.T) {
	key := []byte{64, 154, 239, 170, 64, 40, 195, 99, 19, 84, 192, 142, 192, 238, 207,
		217}
	sharedKey := []byte{25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133,
		74, 82}
	expectedWrappedKey := []byte{164, 255, 251, 1, 64, 200, 65, 200, 34, 197, 81, 143, 43, 211, 240,
		38, 191, 161, 181, 117, 119, 68, 44, 80}

	wrappedKey, err := AesKeyWrap(sharedKey, key)
	if err != nil {
		t.Fatal("AesKeyWrap: ", err)
	}

	if !bytes.Equal(expectedWrappedKey, wrappedKey) {
		t.Fatalf("Unexpected wrapped key:\n\t%v\n\t%v", expectedWrappedKey, wrappedKey)
	}
}

// A.1.8 - JSON Web Encryption
func TestAESKeyUnwrap(t *testing.T) {
	sharedKey := []byte{25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133,
		74, 82}
	wrappedKey := []byte{164, 255, 251, 1, 64, 200, 65, 200, 34, 197, 81, 143, 43, 211, 240,
		38, 191, 161, 181, 117, 119, 68, 44, 80}
	expectedKey := []byte{64, 154, 239, 170, 64, 40, 195, 99, 19, 84, 192, 142, 192, 238, 207,
		217}

	key, err := AesKeyUnwrap(sharedKey, wrappedKey)
	if err != nil {
		t.Fatal("AesKeyUnwrap: ", err)
	}

	if !bytes.Equal(expectedKey, key) {
		t.Fatalf("Unexpected wrapped key:\n\t%v\n\t%v", expectedKey, key)
	}
}
