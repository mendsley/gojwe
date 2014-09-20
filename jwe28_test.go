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
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"
)

func keyFromJWK(jwk string) (crypto.PrivateKey, error) {
	var key struct {
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
		D   string `json:"d"`
		K   string `json:"k"`
	}
	err := json.Unmarshal([]byte(jwk), &key)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal key: %v", err)
	}

	switch key.Kty {
	case "RSA":
		if key.N == "" || key.E == "" || key.D == "" {
			return nil, errors.New("Malformed JWS RSA key")
		}

		// decode exponent
		data, err := safeDecode(key.E)
		if err != nil {
			return nil, errors.New("Malformed JWS RSA key")
		}
		if len(data) < 4 {
			ndata := make([]byte, 4)
			copy(ndata[4-len(data):], data)
			data = ndata
		}

		privKey := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: &big.Int{},
				E: int(binary.BigEndian.Uint32(data[:])),
			},
			D: &big.Int{},
		}

		data, err = safeDecode(key.N)
		if err != nil {
			return nil, errors.New("Malformed JWS RSA key")
		}
		privKey.PublicKey.N.SetBytes(data)

		data, err = safeDecode(key.D)
		if err != nil {
			return nil, errors.New("Malformed JWS RSA key")
		}
		privKey.D.SetBytes(data)

		return privKey, nil
	case "oct":
		if key.K == "" {
			return nil, errors.New("Malformed JWS octect key")
		}

		data, err := safeDecode(key.K)
		if err != nil {
			return nil, errors.New("Malformed JWS octect key")
		}

		return data, nil
	default:
		return nil, fmt.Errorf("Unknown JWS key type %s", key.Kty)
	}
}

// A.1 - Example JWE using RSAES OAEP and AES GCM
func TestDecode28_RSAES_OAEP_AES_GCM(t *testing.T) {
	const jwe = `eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ`
	const key = `{"kty":"RSA","n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw","e":"AQAB","d":"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ"}`

	privKey, err := keyFromJWK(key)
	if err != nil {
		t.Fatal("keyFromJWK: ", err)
	}

	data, err := VerifyAndDecrypt(jwe, privKey)
	if err != nil {
		t.Fatal("VerifyAndDecrypt failed: ", err)
	}

	if string(data) != "The true sign of intelligence is not knowledge but imagination." {
		t.Fatalf("Unexpected plain text: %v", data)
	}
}

// A.2 - Example JWE using RSAES-PKCS1-V1_5 and AES_128_CBC_HMAC_SHA_256
func TestDecode28_RSAES_PKCS1_V1_5_AES_128_CBC_HMAC_SHA256(t *testing.T) {
	const jwe = `eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.9hH0vgRfYgPnAHOd8stkvw`
	const key = `{"kty":"RSA","n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw","e":"AQAB","d":"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"}`

	privKey, err := keyFromJWK(key)
	if err != nil {
		t.Fatal("keyFromJWK: ", err)
	}

	data, err := VerifyAndDecrypt(jwe, privKey)
	if err != nil {
		t.Fatal("VerifyAndDecrypt failed: ", err)
	}

	if string(data) != "Live long and prosper." {
		t.Fatalf("Unexpected plain text: %v", data)
	}
}

// A.3 - Example JWE using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
func TestDecode28_AES_WRAP_AES_128_CBC_MHAC_SHA_256(t *testing.T) {
	const jwe = `eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ`
	const key = `{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}`

	privKey, err := keyFromJWK(key)
	if err != nil {
		t.Fatal("keyFromJWK: ", err)
	}

	data, err := VerifyAndDecrypt(jwe, privKey)
	if err != nil {
		t.Fatal("VerifyAndDecrypt failed: ", err)
	}

	if string(data) != "Live long and prosper." {
		t.Fatalf("Unexpected plain text: %v", data)
	}
}
