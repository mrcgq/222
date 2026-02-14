


// =============================================================================
// 文件: internal/crypto/crypto_test.go
// =============================================================================





package crypto

import (
	"bytes"
	"testing"
)

func TestGeneratePSK(t *testing.T) {
	psk, err := GeneratePSK()
	if err != nil {
		t.Fatalf("生成 PSK 失败: %v", err)
	}
	if len(psk) == 0 {
		t.Fatal("PSK 为空")
	}
	t.Logf("生成的 PSK: %s", psk)
}

func TestEncryptDecrypt(t *testing.T) {
	psk, _ := GeneratePSK()
	c, err := New(psk, 30)
	if err != nil {
		t.Fatalf("创建加密器失败: %v", err)
	}

	plaintext := []byte("Hello, Phantom Server!")
	
	encrypted, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	decrypted, err := c.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("解密结果不匹配: got %v, want %v", decrypted, plaintext)
	}
}

func TestReplayProtection(t *testing.T) {
	psk, _ := GeneratePSK()
	c, err := New(psk, 30)
	if err != nil {
		t.Fatalf("创建加密器失败: %v", err)
	}

	plaintext := []byte("test replay")
	encrypted, _ := c.Encrypt(plaintext)

	// 第一次解密应该成功
	_, err = c.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("第一次解密失败: %v", err)
	}

	// 第二次解密应该失败（重放攻击）
	_, err = c.Decrypt(encrypted)
	if err == nil {
		t.Fatal("应该检测到重放攻击")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	psk, _ := GeneratePSK()
	c, _ := New(psk, 30)
	data := make([]byte, 1400)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.Encrypt(data)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	psk, _ := GeneratePSK()
	c, _ := New(psk, 30)
	data := make([]byte, 1400)
	encrypted, _ := c.Encrypt(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 每次需要重新加密，因为有重放保护
		enc, _ := c.Encrypt(data)
		_, _ = c.Decrypt(enc)
	}
	_ = encrypted
}


