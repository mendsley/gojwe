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

// A.4 - Example Key Derivation for "enc" value "A128CBC+HS246"
func TestConcat_A128CBC_HS256(t *testing.T) {
	cmk := []byte{4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
		206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
		44, 207}

	expectedEncKey := []byte{203, 165, 180, 113, 62, 195, 22, 98, 91, 153, 210, 38, 112, 35, 230,
		236}
	expectedMacKey := []byte{218, 24, 160, 17, 160, 50, 235, 35, 216, 209, 100, 174, 155, 163,
		10, 117, 180, 111, 172, 200, 127, 201, 206, 173, 40, 45, 58, 170, 35,
		93, 9, 60}

	encKey, macKey := concatKDF(cmk, "A128CBC+HS256", 128, 256)
	if !bytes.Equal(encKey, expectedEncKey) {
		t.Fatalf("Mismatching encryption key: %v", encKey)
	}
	if !bytes.Equal(macKey, expectedMacKey) {
		t.Fatalf("Mismatching integrity key: %v", macKey)
	}
}

// A.5 - Example Key Derivation for "enc" value "A256CBC+HS512"
func TestConcat_A256CBC_HS512(t *testing.T) {
	cmk := []byte{148, 116, 199, 126, 2, 117, 233, 76, 150, 149, 89, 193, 61, 34, 239,
		226, 109, 71, 59, 160, 192, 140, 150, 235, 106, 204, 49, 176, 68,
		119, 13, 34, 49, 19, 41, 69, 5, 20, 252, 145, 104, 129, 137, 138, 67,
		23, 153, 83, 81, 234, 82, 247, 48, 211, 41, 130, 35, 124, 45, 156,
		249, 7, 225, 168}

	expectedEncKey := []byte{157, 19, 75, 205, 31, 190, 110, 46, 117, 217, 137, 19, 116, 166,
		126, 60, 18, 244, 226, 114, 38, 153, 78, 198, 26, 0, 181, 168, 113,
		45, 149, 89}
	expectedMacKey := []byte{81, 249, 131, 194, 25, 166, 147, 155, 47, 249, 146, 160, 200, 236,
		115, 72, 103, 248, 228, 30, 130, 225, 164, 61, 105, 172, 198, 31,
		137, 170, 215, 141, 27, 247, 73, 236, 125, 113, 151, 33, 0, 251, 72,
		53, 72, 63, 146, 117, 247, 13, 49, 20, 210, 169, 232, 156, 118, 1,
		16, 45, 29, 21, 15, 208}

	encKey, macKey := concatKDF(cmk, "A256CBC+HS512", 256, 512)
	if !bytes.Equal(encKey, expectedEncKey) {
		t.Fatalf("Mismatching encryption key: %v", encKey)
	}
	if !bytes.Equal(macKey, expectedMacKey) {
		t.Fatalf("Mismatching integrity key: %v", macKey)
	}
}
