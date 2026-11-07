package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	// salt 长度，Argon2id 推荐至少 16 字节
	kdfSaltLen = 16
	// AES-GCM 标准 nonce 长度，长度不符时 Open 会 panic
	gcmNonceLen = 12
	// AES-GCM 认证标签长度，密文至少需要包含标签
	gcmTagLen = 16
	// 同时执行的 KDF 数量上限。单次 Argon2id 使用 32 MiB 内存，
	// 限制并发可避免恶意请求耗尽 CPU 和内存。
	maxConcurrentKDF = 4
)

// Argon2id 版本与对应参数map
var kdfVersionParams = map[int]Argon2Params{
	1: {Time: 4, MemoryKiB: 32 * 1024, Threads: 1, KeyLen: 32}, // v1
}

// kdfSemaphore 限制同时执行的 KDF 数量
var kdfSemaphore = make(chan struct{}, maxConcurrentKDF)

type Argon2Params struct {
	Time      uint32 //  迭代次数
	MemoryKiB uint32 //  内存（KiB）
	Threads   uint8  //  并行度
	KeyLen    uint32 //  密钥长度 (usually 32)
}

type EncryptedData struct {
	Version int    `json:"version"` // 版本 从 1 开始
	Salt    string `json:"salt"`    // base64 编码的盐
	Nonce   string `json:"nonce"`   // base64 编码的随机数
	Cipher  string `json:"cipher"`  // base64 编码的密文（含认证标签）
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

// deriveKey 在并发信号量保护下执行 Argon2id 派生密钥
func deriveKey(password string, salt []byte, params Argon2Params) []byte {
	kdfSemaphore <- struct{}{}
	defer func() {
		<-kdfSemaphore
	}()
	return argon2.IDKey([]byte(password), salt, params.Time, params.MemoryKiB, params.Threads, params.KeyLen)
}

// Encrypt ---- 加密 ----
// password: 明文密码/秘密字符串
// plaintext: 待加密数据 bytes
// 返回 EncryptedData 序列化的 JSON bytes
func Encrypt(password string, plaintext []byte) ([]byte, error) {
	// 版本
	version := 1
	// 随机生成 salt 与 nonce
	salt := mustRandomBytes(kdfSaltLen)   // 16 bytes salt for Argon2
	nonce := mustRandomBytes(gcmNonceLen) // 12 bytes recommended for AES-GCM

	argon2Params := kdfVersionParams[version]
	// 派生 key
	key := deriveKey(password, salt, argon2Params)

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
		Version: version,
		Salt:    b64Encode(salt),
		Nonce:   b64Encode(nonce),
		Cipher:  b64Encode(ciphertext),
	}
	// 清理 key
	zeroBytes(key)
	return json.Marshal(env)
}

// Decrypt ---- 解密 ----
// password: 密码/秘密字符串
// jsonBlob: EncryptedData 序列化的 JSON bytes
func Decrypt(password string, jsonBlob []byte) ([]byte, error) {
	var enc EncryptedData
	if err := json.Unmarshal(jsonBlob, &enc); err != nil {
		return nil, err
	}

	// 读取参数
	argon2Params, ok := kdfVersionParams[enc.Version]
	if !ok {
		return nil, fmt.Errorf("unsupported version: %d", enc.Version)
	}
	salt, err := b64Decode(enc.Salt)
	if err != nil {
		return nil, err
	}
	nonce, err := b64Decode(enc.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := b64Decode(enc.Cipher)
	if err != nil {
		return nil, err
	}

	// 在运行昂贵的 KDF 之前校验长度。AES-GCM 的 Open 在 nonce 长度不是
	// 12 字节时会 panic，必须提前拒绝；salt 和密文长度同样需要在可控范围内。
	if len(salt) != kdfSaltLen {
		return nil, fmt.Errorf("invalid salt length: %d", len(salt))
	}
	if len(nonce) != gcmNonceLen {
		return nil, fmt.Errorf("invalid nonce length: %d", len(nonce))
	}
	if len(ciphertext) < gcmTagLen {
		return nil, fmt.Errorf("invalid ciphertext length: %d", len(ciphertext))
	}

	// 派生 key
	key := deriveKey(password, salt, argon2Params)

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
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	// 清理 key
	zeroBytes(key)
	if err != nil {
		// 解密或认证失败，AES-GCM 自身已做认证校验
		return nil, err
	}
	return plaintext, nil
}
