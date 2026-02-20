// =============================================================================
// 文件: internal/transport/common.go
// 描述: 传输层通用定义
// =============================================================================
package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// =============================================================================
// 常量
// =============================================================================

const (
	ReadTimeout  = 5 * time.Minute
	WriteTimeout = 30 * time.Second
	MaxFrameSize = 64 * 1024 // 64KB
)

// =============================================================================
// 帧读写器
// =============================================================================

// FrameReader 帧读取器
type FrameReader struct {
	conn    net.Conn
	timeout time.Duration
}

// NewFrameReader 创建帧读取器
func NewFrameReader(conn net.Conn, timeout time.Duration) *FrameReader {
	return &FrameReader{
		conn:    conn,
		timeout: timeout,
	}
}

// ReadFrame 读取一帧数据
func (r *FrameReader) ReadFrame() ([]byte, error) {
	if r.timeout > 0 {
		r.conn.SetReadDeadline(time.Now().Add(r.timeout))
	}

	// 读取长度头 (2字节)
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r.conn, lenBuf); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(lenBuf)
	if length == 0 || length > MaxFrameSize {
		return nil, fmt.Errorf("无效帧长度: %d", length)
	}

	// 读取数据
	data := make([]byte, length)
	if _, err := io.ReadFull(r.conn, data); err != nil {
		return nil, err
	}

	return data, nil
}

// FrameWriter 帧写入器
type FrameWriter struct {
	conn    net.Conn
	timeout time.Duration
}

// NewFrameWriter 创建帧写入器
func NewFrameWriter(conn net.Conn, timeout time.Duration) *FrameWriter {
	return &FrameWriter{
		conn:    conn,
		timeout: timeout,
	}
}

// WriteFrame 写入一帧数据
func (w *FrameWriter) WriteFrame(data []byte) error {
	if len(data) > MaxFrameSize {
		return fmt.Errorf("帧数据过大: %d > %d", len(data), MaxFrameSize)
	}

	if w.timeout > 0 {
		w.conn.SetWriteDeadline(time.Now().Add(w.timeout))
	}

	// 写入长度头
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(data)))
	if _, err := w.conn.Write(lenBuf); err != nil {
		return err
	}

	// 写入数据
	if _, err := w.conn.Write(data); err != nil {
		return err
	}

	return nil
}
