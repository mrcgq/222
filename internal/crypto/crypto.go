// =============================================================================
// 文件: internal/crypto/crypto.go
// =============================================================================

package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	PSKSize       = 32
	UserIDSize    = 4
	TimestampSize = 2
	NonceSize     = chacha20poly1305.NonceSize
	TagSize       = chacha20poly1305.Overhead
	HeaderSize    = UserIDSize + TimestampSize
)

// Crypto 加密器
type Crypto struct {
	psk        []byte
	userID     [UserIDSize]byte
	timeWindow int

	aeadCache sync.Map // window -> cachedAEAD

	recvGuard *ReplayGuard
	sendGuard *ReplayGuard

	mu sync.RWMutex
}

// cachedAEAD 带时间戳的缓存 AEAD
type cachedAEAD struct {
	aead      cipher.AEAD
	createdAt time.Time
}

// New 创建加密器
func New(pskBase64 string, timeWindow int) (*Crypto, error) {
	psk, err := base64.StdEncoding.DecodeString(pskBase64)
	if err != nil {
		return nil, fmt.Errorf("PSK 解码失败: %w", err)
	}
	if len(psk) != PSKSize {
		return nil, fmt.Errorf("PSK 长度必须是 %d 字节", PSKSize)
	}

	c := &Crypto{
		psk:        psk,
		timeWindow: timeWindow,
		recvGuard:  NewReplayGuard(),
		sendGuard:  NewReplayGuard(),
	}

	// 派生 UserID
	reader := hkdf.New(sha256.New, psk, nil, []byte("phantom-userid-v3"))
	if _, err := io.ReadFull(reader, c.userID[:]); err != nil {
		return nil, fmt.Errorf("派生 UserID 失败: %w", err)
	}

	// 启动 AEAD 缓存清理
	go c.cleanupAEADLoop()

	return c, nil
}

// GetUserID 返回 UserID
func (c *Crypto) GetUserID() [UserIDSize]byte {
	return c.userID
}

// Encrypt 加密数据
func (c *Crypto) Encrypt(plaintext []byte) ([]byte, error) {
	window := c.currentWindow()
	aead, err := c.getAEAD(window)
	if err != nil {
		return nil, err
	}

	// 生成唯一 Nonce
	nonce := make([]byte, NonceSize)
	for attempts := 0; attempts < 10; attempts++ {
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}

		if c.sendGuard.CheckOnly(nonce) {
			c.sendGuard.Mark(nonce)
			break
		}

		if attempts == 9 {
			return nil, fmt.Errorf("无法生成唯一 Nonce")
		}
	}

	timestamp := uint16(time.Now().Unix() & 0xFFFF)

	// 输出: UserID(4) + Timestamp(2) + Nonce(12) + Ciphertext + Tag(16)
	output := make([]byte, HeaderSize+NonceSize+len(plaintext)+TagSize)
	copy(output[:UserIDSize], c.userID[:])
	binary.BigEndian.PutUint16(output[UserIDSize:HeaderSize], timestamp)
	copy(output[HeaderSize:HeaderSize+NonceSize], nonce)

	aead.Seal(output[HeaderSize+NonceSize:HeaderSize+NonceSize], nonce, plaintext, output[:HeaderSize])

	return output, nil
}

// Decrypt 解密数据
func (c *Crypto) Decrypt(data []byte) ([]byte, error) {
	minSize := HeaderSize + NonceSize + TagSize
	if len(data) < minSize {
		return nil, fmt.Errorf("数据太短")
	}

	// 验证 UserID
	var userID [UserIDSize]byte
	copy(userID[:], data[:UserIDSize])
	if userID != c.userID {
		return nil, fmt.Errorf("UserID 不匹配")
	}

	// 验证时间戳
	timestamp := binary.BigEndian.Uint16(data[UserIDSize:HeaderSize])
	if !c.validateTimestamp(timestamp) {
		return nil, fmt.Errorf("时间戳无效")
	}

	nonce := data[HeaderSize : HeaderSize+NonceSize]

	// 重放检查
	if !c.recvGuard.CheckOnly(nonce) {
		return nil, fmt.Errorf("重放攻击")
	}

	ciphertext := data[HeaderSize+NonceSize:]
	header := data[:HeaderSize]

	// 修复：尝试多个时间窗口，提供更好的容错性
	windows := c.validWindows()
	for _, window := range windows {
		aead, err := c.getAEAD(window)
		if err != nil {
			continue
		}
		if plaintext, err := aead.Open(nil, nonce, ciphertext, header); err == nil {
			// 解密成功后标记 nonce
			c.recvGuard.Mark(nonce)
			return plaintext, nil
		}
	}

	return nil, fmt.Errorf("解密失败")
}

// Stats 返回统计信息
func (c *Crypto) Stats() (recv, send ReplayStats) {
	return c.recvGuard.Stats(), c.sendGuard.Stats()
}

// MemoryUsage 返回内存使用估算
func (c *Crypto) MemoryUsage() int64 {
	return c.recvGuard.MemoryUsage() + c.sendGuard.MemoryUsage()
}

func (c *Crypto) currentWindow() int64 {
	return time.Now().Unix() / int64(c.timeWindow)
}

// validWindows 返回有效的时间窗口列表
// 修复：确保在窗口切换瞬间有足够的容错性
func (c *Crypto) validWindows() []int64 {
	w := c.currentWindow()
	// 返回当前窗口、前一个窗口和后一个窗口
	// 顺序：当前 -> 前一个 -> 后一个（按概率排序）
	return []int64{w, w - 1, w + 1}
}

func (c *Crypto) getAEAD(window int64) (cipher.AEAD, error) {
	if v, ok := c.aeadCache.Load(window); ok {
		cached := v.(*cachedAEAD)
		return cached.aead, nil
	}

	salt := make([]byte, 8)
	binary.BigEndian.PutUint64(salt, uint64(window))
	reader := hkdf.New(sha256.New, c.psk, salt, []byte("phantom-key-v3"))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("派生密钥失败: %w", err)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("创建 AEAD 失败: %w", err)
	}

	cached := &cachedAEAD{
		aead:      aead,
		createdAt: time.Now(),
	}
	c.aeadCache.Store(window, cached)

	return aead, nil
}

func (c *Crypto) validateTimestamp(ts uint16) bool {
	current := uint16(time.Now().Unix() & 0xFFFF)
	diff := int(current) - int(ts)

	// 处理时间戳回绕
	if diff < -32768 {
		diff += 65536
	} else if diff > 32768 {
		diff -= 65536
	}
	if diff < 0 {
		diff = -diff
	}

	// 修复：增加容错范围，允许 timeWindow * 3 的偏差
	// 这可以更好地处理网络延迟和时钟偏差
	return diff <= c.timeWindow*3
}

// cleanupAEADLoop 定期清理过期的 AEAD 缓存
// 修复：保留更长时间的缓存，提供窗口切换时的过渡期
func (c *Crypto) cleanupAEADLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cw := c.currentWindow()
		now := time.Now()

		c.aeadCache.Range(func(key, value interface{}) bool {
			w := key.(int64)
			cached := value.(*cachedAEAD)

			// 保留条件：
			// 1. 窗口在有效范围内 (当前 ± 2)
			// 2. 或者缓存时间不超过 2 分钟（提供额外的过渡期）
			windowValid := cw-w <= 2 && w-cw <= 2
			timeValid := now.Sub(cached.createdAt) < 2*time.Minute

			if !windowValid && !timeValid {
				c.aeadCache.Delete(key)
			}
			return true
		})
	}
}

// GeneratePSK 生成新的 PSK
func GeneratePSK() (string, error) {
	psk := make([]byte, PSKSize)
	if _, err := rand.Read(psk); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(psk), nil
}
