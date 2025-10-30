package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

// Argon2id 默认参数
var defaultArgon2Params = Argon2Params{
	TimeCost:      2,
	MemoryCostKiB: 8 * 1024, // 8MB
	Parallelism:   2,
	HashLen:       32,
}

type Argon2Params struct {
	TimeCost      uint32 //  迭代次数
	MemoryCostKiB uint32 //  内存（KiB）
	Parallelism   uint8  //  并行度
	HashLen       uint32 //  密钥长度 (usually 32)
}

type KDFParams struct {
	Salt string `json:"salt"` // base64
}

type CipherParams struct {
	Nonce string `json:"nonce"` // base64
}

type EncryptedData struct {
	//Version      string       `json:"version"`
	KDF          string       `json:"kdf"`
	KDFParams    KDFParams    `json:"kdf_params"`
	Cipher       string       `json:"cipher"`
	CipherParams CipherParams `json:"cipher_params"`
	Ciphertext   string       `json:"ciphertext"` // base64(ciphertext || tag)
}

// ---- helpers ----
func mustRandomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		panic(err)
	}
	return b
}

func b64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func b64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// 覆盖清零切片里的敏感数据（尽最大努力）
func zeroBytes(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}

// EncryptWithParams ---- 加密 ----
// password: 明文密码/秘密字符串
// plaintext: 待加密数据
// 返回 EncryptedData 序列化的 JSON bytes
func EncryptWithParams(password string, plaintext []byte, argon2Params Argon2Params) ([]byte, error) {
	// 随机生成 salt 与 nonce
	salt := mustRandomBytes(16)  // 16 bytes salt for Argon2
	nonce := mustRandomBytes(12) // 12 bytes recommended for AES-GCM

	// 派生 key
	key := argon2.IDKey([]byte(password), salt, argon2Params.TimeCost, argon2Params.MemoryCostKiB, argon2Params.Parallelism, argon2Params.HashLen)

	// AES-GCM 加密
	block, err := aes.NewCipher(key)
	if err != nil {
		zeroBytes(key)
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		zeroBytes(key)
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil) // includes auth tag at end

	// 构造加密数据 JSON
	env := EncryptedData{
		//Version: "1",
		KDF: "argon2id",
		KDFParams: KDFParams{
			Salt: b64Encode(salt),
		},
		Cipher: "aes-256-gcm",
		CipherParams: CipherParams{
			Nonce: b64Encode(nonce),
		},
		Ciphertext: b64Encode(ciphertext),
	}

	// 清理 key
	zeroBytes(key)

	return json.Marshal(env)
}

func Encrypt(password string, plaintext []byte) ([]byte, error) {
	return EncryptWithParams(password, plaintext, defaultArgon2Params)
}

// DecryptWithParams ---- 解密 ----
// password: 密码/秘密字符串
// jsonBlob: EncryptedData 序列化的 JSON bytes
func DecryptWithParams(password string, jsonBlob []byte, argon2Params Argon2Params) ([]byte, error) {
	var enc EncryptedData
	if err := json.Unmarshal(jsonBlob, &enc); err != nil {
		return nil, err
	}

	if enc.KDF != "argon2id" {
		return nil, errors.New("unsupported kdf")
	}
	if enc.Cipher != "aes-256-gcm" {
		return nil, errors.New("unsupported cipher")
	}

	// 读取参数
	kp := enc.KDFParams
	salt, err := b64Decode(kp.Salt)
	if err != nil {
		return nil, err
	}
	nonce, err := b64Decode(enc.CipherParams.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := b64Decode(enc.Ciphertext)
	if err != nil {
		return nil, err
	}

	// 派生 key
	key := argon2.IDKey([]byte(password), salt, argon2Params.TimeCost, argon2Params.MemoryCostKiB, argon2Params.Parallelism, argon2Params.HashLen)

	// AES-GCM 解密
	block, err := aes.NewCipher(key)
	if err != nil {
		zeroBytes(key)
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		zeroBytes(key)
		return nil, err
	}
	plaintext, err := aesgcm.Open(nil, nonce, ct, nil)
	// 清理 key
	zeroBytes(key)
	if err != nil {
		return nil, err // 解密或认证失败
	}
	return plaintext, nil
}

func Decrypt(password string, jsonBlob []byte) ([]byte, error) {
	return DecryptWithParams(password, jsonBlob, defaultArgon2Params)
}
