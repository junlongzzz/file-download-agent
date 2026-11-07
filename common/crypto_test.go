package common

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte(`{"url":"https://example.com/file.zip","filename":"file.zip"}`)
	blob, err := Encrypt("secret", plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	got, err := Decrypt("secret", blob)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("Decrypt() = %q, want %q", got, plaintext)
	}
}

// 非法的 salt/nonce/cipher 长度必须在运行 KDF 之前被拒绝，
// 尤其是 nonce 长度不对时 AES-GCM 的 Open 会 panic。
func TestDecryptRejectsInvalidLengths(t *testing.T) {
	tests := []struct {
		name   string
		salt   []byte
		nonce  []byte
		cipher []byte
	}{
		{name: "invalid salt", salt: make([]byte, kdfSaltLen-1), nonce: make([]byte, gcmNonceLen), cipher: make([]byte, gcmTagLen)},
		{name: "invalid nonce", salt: make([]byte, kdfSaltLen), nonce: make([]byte, gcmNonceLen-1), cipher: make([]byte, gcmTagLen)},
		{name: "short ciphertext", salt: make([]byte, kdfSaltLen), nonce: make([]byte, gcmNonceLen), cipher: make([]byte, gcmTagLen-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blob, err := json.Marshal(EncryptedData{
				Version: 1,
				Salt:    base64.StdEncoding.EncodeToString(tt.salt),
				Nonce:   base64.StdEncoding.EncodeToString(tt.nonce),
				Cipher:  base64.StdEncoding.EncodeToString(tt.cipher),
			})
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			if _, err := Decrypt("secret", blob); err == nil {
				t.Fatal("Decrypt() error = nil, want error")
			}
		})
	}
}
