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
	"crypto/rsa"
	"math/big"
	"testing"
)

// A.1 - Example JWE using RSAES OAEP and AES GCM
func TestDecode7_RSAES_OAEP_AES_GCM(t *testing.T) {
	const jwe = `eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.M2XxpbORKezKSzzQL_95-GjiudRBTqn_omS8z9xgoRb7L0Jw5UsEbxmtyHn2T71mrZLkjg4Mp8gbhYoltPkEOHvAopz25-vZ8C2e1cOaAo5WPcbSIuFcB4DjBOM3t0UAO6JHkWLuAEYoe58lcxIQneyKdaYSLbV9cKqoUoFQpvKWYRHZbfszIyfsa18rmgTjzrtLDTPnc09DSJE24aQ8w3i8RXEDthW9T1J6LsTH_vwHdwUgkI-tC2PNeGrnM-dNSfzF3Y7-lwcGy0FsdXkPXytvDV7y4pZeeUiQ-0VdibIN2AjjfW60nfrPuOjepMFG6BBBbR37pHcyzext9epOAQ.48V1_ALb6US04U3b._e21tGGhac_peEFkLXr2dMPUZiUkrw.7V5ZDko0v_mf2PAc4JMiUg`

	privKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: &big.Int{},
			E: 65537,
		},
		D: &big.Int{},
	}
	privKey.PublicKey.N.SetBytes([]byte{161, 168, 84, 34, 133, 176, 208, 173, 46, 176, 163,
		110, 57, 30, 135, 227, 9, 31, 226, 128, 84, 92, 116,
		241, 70, 248, 27, 227, 193, 62, 5, 91, 241, 145, 224,
		205, 141, 176, 184, 133, 239, 43, 81, 103, 9, 161,
		153, 157, 179, 104, 123, 51, 189, 34, 152, 69, 97,
		69, 78, 93, 140, 131, 87, 182, 169, 101, 92, 142, 3,
		22, 167, 8, 212, 56, 35, 79, 210, 222, 192, 208, 252,
		49, 109, 138, 173, 253, 210, 166, 201, 63, 102, 74,
		5, 158, 41, 90, 144, 108, 160, 79, 10, 89, 222, 231,
		172, 31, 227, 197, 0, 19, 72, 81, 138, 78, 136, 221,
		121, 118, 196, 17, 146, 10, 244, 188, 72, 113, 55,
		221, 162, 217, 171, 27, 57, 233, 210, 101, 236, 154,
		199, 56, 138, 239, 101, 48, 198, 186, 202, 160, 76,
		111, 234, 71, 57, 183, 5, 211, 171, 136, 126, 64, 40,
		75, 58, 89, 244, 254, 107, 84, 103, 7, 236, 69, 163,
		18, 180, 251, 58, 153, 46, 151, 174, 12, 103, 197,
		181, 161, 162, 55, 250, 235, 123, 110, 17, 11, 158,
		24, 47, 133, 8, 199, 235, 107, 126, 130, 246, 73,
		195, 20, 108, 202, 176, 214, 187, 45, 146, 182, 118,
		54, 32, 200, 61, 201, 71, 243, 1, 255, 131, 84, 37,
		111, 211, 168, 228, 45, 192, 118, 27, 197, 235, 232,
		36, 10, 230, 248, 190, 82, 182, 140, 35, 204, 108,
		190, 253, 186, 186, 27})
	privKey.D.SetBytes([]byte{144, 183, 109, 34, 62, 134, 108, 57, 44, 252, 10,
		66, 73, 54, 16, 181, 233, 92, 54, 219, 101, 42, 35,
		178, 63, 51, 43, 92, 119, 136, 251, 41, 53, 23, 191,
		164, 164, 60, 88, 227, 229, 152, 228, 213, 149, 228,
		169, 237, 104, 71, 151, 75, 88, 252, 216, 77, 251,
		231, 28, 97, 88, 193, 215, 202, 248, 216, 121, 195,
		211, 245, 250, 112, 71, 243, 61, 129, 95, 39, 244,
		122, 225, 217, 169, 211, 165, 48, 253, 220, 59, 122,
		219, 42, 86, 223, 32, 236, 39, 48, 103, 78, 122, 216,
		187, 88, 176, 89, 24, 1, 42, 177, 24, 99, 142, 170,
		1, 146, 43, 3, 108, 64, 194, 121, 182, 95, 187, 134,
		71, 88, 96, 134, 74, 131, 167, 69, 106, 143, 121, 27,
		72, 44, 245, 95, 39, 194, 179, 175, 203, 122, 16,
		112, 183, 17, 200, 202, 31, 17, 138, 156, 184, 210,
		157, 184, 154, 131, 128, 110, 12, 85, 195, 122, 241,
		79, 251, 229, 183, 117, 21, 123, 133, 142, 220, 153,
		9, 59, 57, 105, 81, 255, 138, 77, 82, 54, 62, 216,
		38, 249, 208, 17, 197, 49, 45, 19, 232, 157, 251,
		131, 137, 175, 72, 126, 43, 229, 69, 179, 117, 82,
		157, 213, 83, 35, 57, 210, 197, 252, 171, 143, 194,
		11, 47, 163, 6, 253, 75, 252, 96, 11, 187, 84, 130,
		210, 7, 121, 78, 91, 79, 57, 251, 138, 132, 220, 60,
		224, 173, 56, 224, 201})

	data, err := VerifyAndDecryptDraft7(jwe, privKey)
	if err != nil {
		t.Fatal("VerifyAndDecryptDraft7 failed: ", err)
	}

	if string(data) != "Live long and prosper." {
		t.Fatalf("Unexpected plain text: %v", data)
	}
}

// A.2 - Example JWE using RSAES-PKCS1-V1_5 and AES CBC
func TestDecode7_RSAES_PKCS1_V1_5_AES_CBC(t *testing.T) {
	const jwe = `eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDK0hTMjU2In0.ZmnlqWgjXyqwjr7cXHys8F79anIUI6J2UWdAyRQEcGBU-KPHsePM910_RoTDGu1IW40Dn0dvcdVEjpJcPPNIbzWcMxDi131Ejeg-b8ViW5YX5oRdYdiR4gMSDDB3mbkInMNUFT-PK5CuZRnHB2rUK5fhPuF6XFqLLZCG5Q_rJm6Evex-XLcNQAJNa1-6CIU12Wj3mPExxw9vbnsQDU7B4BfmhdyiflLA7Ae5ZGoVRl3A__yLPXxRjHFhpOeDp_adx8NyejF5cz9yDKULugNsDMdlHeJQOMGVLYaSZt3KP6aWNSqFA1PHDg-10ceuTEtq_vPE4-Gtev4N4K4Eudlj4Q.AxY8DCtDaGlsbGljb3RoZQ.Rxsjg6PIExcmGSF7LnSEkDqWIKfAw1wZz2XpabV5PwQsolKwEauWYZNE9Q1hZJEZ.8LXqMd0JLGsxMaB5uoNaMpg7uUW_p40RlaZHCwMIyzk`

	privKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: &big.Int{},
			E: 65537,
		},
		D: &big.Int{},
	}
	privKey.PublicKey.N.SetBytes([]byte{177, 119, 33, 13, 164, 30, 108, 121, 207, 136, 107,
		242, 12, 224, 19, 226, 198, 134, 17, 71, 173, 75, 42,
		61, 48, 162, 206, 161, 97, 108, 185, 234, 226, 219,
		118, 206, 118, 5, 169, 224, 60, 181, 90, 85, 51, 123,
		6, 224, 4, 122, 29, 230, 151, 12, 244, 127, 121, 25,
		4, 85, 220, 144, 215, 110, 130, 17, 68, 228, 129,
		138, 7, 130, 231, 40, 212, 214, 17, 179, 28, 124,
		151, 178, 207, 20, 14, 154, 222, 113, 176, 24, 198,
		73, 211, 113, 9, 33, 178, 80, 13, 25, 21, 25, 153,
		212, 206, 67, 154, 147, 70, 194, 192, 183, 160, 83,
		98, 236, 175, 85, 23, 97, 75, 199, 177, 73, 145, 50,
		253, 206, 32, 179, 254, 236, 190, 82, 73, 67, 129,
		253, 252, 220, 108, 136, 138, 11, 192, 1, 36, 239,
		228, 55, 81, 113, 17, 25, 140, 63, 239, 146, 3, 172,
		96, 60, 227, 233, 64, 255, 224, 173, 225, 228, 229,
		92, 112, 72, 99, 97, 26, 87, 187, 123, 46, 50, 90,
		202, 117, 73, 10, 153, 47, 224, 178, 163, 77, 48, 46,
		154, 33, 148, 34, 228, 33, 172, 216, 89, 46, 225,
		127, 68, 146, 234, 30, 147, 54, 146, 5, 133, 45, 78,
		254, 85, 55, 75, 213, 86, 194, 218, 215, 163, 189,
		194, 54, 6, 83, 36, 18, 153, 53, 7, 48, 89, 35, 66,
		144, 7, 65, 154, 13, 97, 75, 55, 230, 132, 3, 13,
		239, 71})
	privKey.D.SetBytes([]byte{84, 80, 150, 58, 165, 235, 242, 123, 217, 55, 38,
		154, 36, 181, 221, 156, 211, 215, 100, 164, 90, 88,
		40, 228, 83, 148, 54, 122, 4, 16, 165, 48, 76, 194,
		26, 107, 51, 53, 179, 165, 31, 18, 198, 173, 78, 61,
		56, 97, 252, 158, 140, 80, 63, 25, 223, 156, 36, 203,
		214, 252, 120, 67, 180, 167, 3, 82, 243, 25, 97, 214,
		83, 133, 69, 16, 104, 54, 160, 200, 41, 83, 164, 187,
		70, 153, 111, 234, 242, 158, 175, 28, 198, 48, 211,
		45, 148, 58, 23, 62, 227, 74, 52, 117, 42, 90, 41,
		249, 130, 154, 80, 119, 61, 26, 193, 40, 125, 10,
		152, 174, 227, 225, 205, 32, 62, 66, 6, 163, 100, 99,
		219, 19, 253, 25, 105, 80, 201, 29, 252, 157, 237,
		69, 1, 80, 171, 167, 20, 196, 156, 109, 249, 88, 0,
		3, 152, 38, 165, 72, 87, 6, 152, 71, 156, 214, 16,
		71, 30, 82, 51, 103, 76, 218, 63, 9, 84, 163, 249,
		91, 215, 44, 238, 85, 101, 240, 148, 1, 82, 224, 91,
		135, 105, 127, 84, 171, 181, 152, 210, 183, 126, 24,
		46, 196, 90, 173, 38, 245, 219, 186, 222, 27, 240,
		212, 194, 15, 66, 135, 226, 178, 190, 52, 245, 74,
		65, 224, 81, 100, 85, 25, 204, 165, 203, 187, 175,
		84, 100, 82, 15, 11, 23, 202, 151, 107, 54, 41, 207,
		3, 136, 229, 134, 131, 93, 139, 50, 182, 204, 93,
		130, 89})

	data, err := VerifyAndDecryptDraft7(jwe, privKey)
	if err != nil {
		t.Fatal("VerifyAndDecryptDraft7 failed: ", err)
	}
	if string(data) != "No matter where you go, there you are." {
		t.Fatal("Wrong decrypted text: %v", data)
	}
}
