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
	"compress/flate"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"strings"
)

type Algorithm string

const (
	ALG_RSA_OAEP     = Algorithm("RSA-OAEP")
	ALG_RSA_OAEP_256 = Algorithm("RSA-OAEP-256")
	ALG_RSA1_5       = Algorithm("RSA1_5")
	ALG_A128KW       = Algorithm("A128KW")
	ALG_A256KW       = Algorithm("A256KW")
)

type EncryptionMethod string

const (
	ENC_A128CBC_HS256_v7 = EncryptionMethod("A128CBC+HS256")
	ENC_A256CBC_HS512_v7 = EncryptionMethod("A256CBC+H512")
	ENC_A128GCM          = EncryptionMethod("A128GCM")
	ENC_A256GCM          = EncryptionMethod("A256GCM")
)

// Verify and decrypt a draft-7 JWE object
func VerifyAndDecryptDraft7(jwe string, key crypto.PrivateKey) ([]byte, error) {
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		return nil, errors.New("Wrong number of parts")
	}

	// decode the JWE header
	var header struct {
		Alg Algorithm        `json:"alg"`
		Enc EncryptionMethod `json:"enc"`
		Zip string           `json:"zip"`
	}
	data, err := safeDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("Malformed header: %v", err)
	}
	err = json.Unmarshal(data, &header)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode header: %v", err)
	}

	var encryptionKey []byte
	encryptionKeyData, err := safeDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("Malformed encryption key: %v", err)
	}

	// decode the encryption key
	switch header.Alg {
	case ALG_RSA_OAEP, ALG_RSA_OAEP_256:
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("Expected an RSA private key. Got %T", key)
		}

		var h hash.Hash
		if header.Alg == ALG_RSA_OAEP {
			h = sha1.New()
		} else if header.Alg == ALG_RSA_OAEP_256 {
			h = sha256.New()
		} else {
			panic("Logic error with algorithm " + header.Alg)
		}

		encryptionKey, err = rsa.DecryptOAEP(h, rand.Reader, rsaKey, encryptionKeyData, nil)
		if err != nil {
			return nil, fmt.Errorf("Failed to decrypt encryption key: %v", err)
		}

	case ALG_RSA1_5:
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("Expected RSA private key. Got %T", key)
		}

		encryptionKey, err = rsa.DecryptPKCS1v15(rand.Reader, rsaKey, encryptionKeyData)
		if err != nil {
			return nil, fmt.Errorf("Failed to decrypt encryption key: %v", err)
		}

	case ALG_A128KW, ALG_A256KW:
		aesKey, ok := key.([]byte)
		if !ok {
			return nil, fmt.Errorf("Expected shared symmetric key ([]byte). Got %T", key)
		}

		encryptionKey, err = AesKeyUnwrap(aesKey, encryptionKeyData)
		if err != nil {
			return nil, fmt.Errorf("Failed to unwrap key: %v", err)
		}

	default:
		return nil, fmt.Errorf("Unsupported ALG keytype %s", header.Alg)
	}

	// decode IV
	iv, err := safeDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("Malformed IV: %v", err)
	}

	// decode cipher text
	cipherText, err := safeDecode(parts[3])
	if err != nil {
		return nil, fmt.Errorf("Malformed cipher text: %v", err)
	}

	// decode authtag
	authTag, err := safeDecode(parts[4])
	if err != nil {
		return nil, fmt.Errorf("Malformed authtag: %v", err)
	}

	// decrypt and verify cipher text
	var plainText []byte

	switch header.Enc {
	case ENC_A128CBC_HS256_v7, ENC_A256CBC_HS512_v7:
		// derive keys
		var encSize, macSize int
		var hfunc func() hash.Hash
		if header.Enc == ENC_A128CBC_HS256_v7 {
			encSize, macSize = 128, 256
			hfunc = sha256.New
		} else if header.Enc == ENC_A256CBC_HS512_v7 {
			encSize, macSize = 256, 512
			hfunc = sha512.New
		} else {
			panic("Bad ENC logic for type: " + header.Enc)
		}

		encKey, macKey := concatKDF(encryptionKey, string(header.Enc), encSize, macSize)

		// verify authtag
		hm := hmac.New(hfunc, macKey)
		io.WriteString(hm, parts[0])
		io.WriteString(hm, ".")
		io.WriteString(hm, parts[1])
		io.WriteString(hm, ".")
		io.WriteString(hm, parts[2])
		io.WriteString(hm, ".")
		io.WriteString(hm, parts[3])
		if !hmac.Equal(authTag, hm.Sum(nil)) {
			return nil, errors.New("Integrity check failed")
		}

		// decrpyt ciphertext (in-place)
		block, err := aes.NewCipher(encKey)
		if err != nil {
			return nil, fmt.Errorf("Failed to create an AES block cipher: %v", err)
		}

		c := cipher.NewCBCDecrypter(block, iv)
		c.CryptBlocks(cipherText, cipherText)
		plainText = cipherText

		// remove PCKS#7 padding
		padding := int(plainText[len(plainText)-1])
		plainText = plainText[:len(plainText)-padding]

	case ENC_A128GCM, ENC_A256GCM:
		// create the "additional data" for the GCM cipher
		additionalData := new(bytes.Buffer)
		additionalData.WriteString(parts[0])
		additionalData.WriteRune('.')
		additionalData.WriteString(parts[1])
		additionalData.WriteRune('.')
		additionalData.WriteString(parts[2])

		// create the authenticating cipher
		block, err := aes.NewCipher(encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("Failed to create an AES block cipher: %v", err)
		}
		c, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("Failed to create GCM cipher: %v", err)
		}

		// decrypt the cipher text (in-place)
		_, err = c.Open(cipherText[:0], iv, append(cipherText, authTag...), additionalData.Bytes())
		if err != nil {
			return nil, fmt.Errorf("Failed to decrypt: %v", err)
		}
		plainText = cipherText

	default:
		return nil, fmt.Errorf("Unsupported ENC keytype %s", header.Enc)
	}

	// need to deflate plain text?
	if header.Zip == "DEF" {
		plainText, err = ioutil.ReadAll(flate.NewReader(bytes.NewReader(plainText)))
		if err != nil {
			return nil, fmt.Errorf("Failed to inflate plain text: %v", err)
		}
	}

	return plainText, nil
}
