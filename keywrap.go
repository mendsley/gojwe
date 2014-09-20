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
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Wrap a key using the AES Key Wrap Algorithm
//   See: RFC 3394
func AesKeyWrap(key, plainText []byte) ([]byte, error) {
	if len(plainText)%8 != 0 {
		return nil, errors.New("plainText must be a multiple of 64 bits")
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to create an AES cipher: %v", err)
	}

	nblocks := len(plainText) / 8

	// 1) Initialize variables.
	var block [aes.BlockSize]byte
	// - Set A = IV, an initial value (see 2.2.3)
	for ii := 0; ii < 8; ii++ {
		block[ii] = 0xA6
	}

	// - For i = 1 to n
	// -   Set R[i] = P[i]
	intermediate := make([]byte, len(plainText))
	copy(intermediate, plainText)

	// 2) Calculate intermediate values.
	for ii := 0; ii < 6; ii++ {
		for jj := 0; jj < nblocks; jj++ {
			// - B = AES(K, A | R[i])
			copy(block[8:], intermediate[jj*8:jj*8+8])
			c.Encrypt(block[:], block[:])

			// - A = MSB(64, B) ^ t where t = (n*j)+1
			t := uint64(ii*nblocks + jj + 1)
			val := binary.BigEndian.Uint64(block[:8]) ^ t
			binary.BigEndian.PutUint64(block[:8], val)

			// - R[i] = LSB(64, B)
			copy(intermediate[jj*8:jj*8+8], block[8:])
		}
	}

	// 3) Output results.
	// - Set C[0] = A
	// - For i = 1 to n
	// -   C[i] = R[i]
	return append(block[:8], intermediate...), nil
}

// Unwrap a key using the AES Key Wrap Algorithm
//   See: RFC 3394
func AesKeyUnwrap(key, cipherText []byte) ([]byte, error) {
	if len(cipherText)%8 != 0 {
		return nil, errors.New("cipherText must by a multiple of 64 bits")
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to create an AES cipher: %v", err)
	}

	nblocks := len(cipherText)/8 - 1

	// 1) Initialize variables.
	var block [aes.BlockSize]byte
	// - Set A = C[0]
	copy(block[:8], cipherText[:8])

	// - For i = 1 to n
	// -   Set R[i] = C[i]
	intermediate := make([]byte, len(cipherText)-8)
	copy(intermediate, cipherText[8:])

	// 2) Compute intermediate values.
	for jj := 5; jj >= 0; jj-- {
		for ii := nblocks - 1; ii >= 0; ii-- {
			// - B = AES-1(K, (A ^ t) | R[i]) where t = n*j+1
			// - A = MSB(64, B)
			t := uint64(jj*nblocks + ii + 1)
			val := binary.BigEndian.Uint64(block[:8]) ^ t
			binary.BigEndian.PutUint64(block[:8], val)

			copy(block[8:], intermediate[ii*8:ii*8+8])
			c.Decrypt(block[:], block[:])

			// - R[i] = LSB(B, 64)
			copy(intermediate[ii*8:ii*8+8], block[8:])
		}
	}

	// 3) Output results.
	// - If A is an appropriate initial value (see 2.2.3),
	for ii := 0; ii < 8; ii++ {
		if block[ii] != 0xA6 {
			return nil, errors.New("Failed to unwrap key")
		}
	}

	// - For i = 1 to n
	// -   P[i] = R[i]
	return intermediate, nil
}
