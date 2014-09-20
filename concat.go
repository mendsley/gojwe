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
	"crypto/sha256"
	"encoding/binary"
)

// concat key derivation function
func concatKDF(masterKey []byte, keyType string, encKeySize, macKeySize int) ([]byte, []byte) {

	// build buffer common to encryption and integrity derivation
	buffer := make([]byte, len(masterKey)+len(keyType)+26)
	binary.BigEndian.PutUint32(buffer[:], uint32(1))
	copy(buffer[4:], masterKey)
	copy(buffer[8+len(masterKey):], keyType)
	binary.BigEndian.PutUint32(buffer[8+len(masterKey)+len(keyType):], uint32(0))
	binary.BigEndian.PutUint32(buffer[12+len(masterKey)+len(keyType):], uint32(0))

	// derive the encryption key
	binary.BigEndian.PutUint32(buffer[4+len(masterKey):], uint32(encKeySize))
	copy(buffer[16+len(masterKey)+len(keyType):], "Encryption")

	h := sha256.New()
	h.Write(buffer)
	encKey := h.Sum(nil)

	// derive the integrity key
	binary.BigEndian.PutUint32(buffer[4+len(masterKey):], uint32(macKeySize))
	copy(buffer[16+len(masterKey)+len(keyType):], "Integrity")

	h.Reset()
	h.Write(buffer[:len(buffer)-1])
	macKey := h.Sum(nil)

	return encKey[:encKeySize/8], macKey[:macKeySize/8]
}
