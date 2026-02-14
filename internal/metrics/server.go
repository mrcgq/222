


// =============================================================================
// 文件: internal/metrics/server.go
// 描述: 健康检查和 Metrics 服务 - Prometheus 标准格式
// =============================================================================
package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/pprof"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsServer 指标服务器
type MetricsServer struct {
	listen      string
	metricsPath string
	healthPath  string
	enablePprof bool

	httpServer *http.Server
	registry   *prometheus.Registry

	healthy     int32
	healthCheck func() HealthStatus

	mu sync.RWMutex
}

// HealthStatus 健康状态
type HealthStatus struct {
	Status     string                     `json:"status"`
	Timestamp  time.Time                  `json:"timestamp"`
	Version    string                     `json:"version"`
	Uptime     time.Duration              `json:"uptime"`
	Components map[string]ComponentHealth `json:"components"`
}

// ComponentHealth 组件健康状态
type ComponentHealth struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// NewMetricsServer 创建指标服务器
func NewMetricsServer(listen, metricsPath, healthPath string, enablePprof bool) *MetricsServer {
	// 创建自定义 registry，避免污染全局
	registry := prometheus.NewRegistry()

	// 注册 Go 运行时收集器
	registry.MustRegister(collectors.NewGoCollector())
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	return &MetricsServer{
		listen:      listen,
		metricsPath: metricsPath,
		healthPath:  healthPath,
		enablePprof: enablePprof,
		healthy:     1,
		registry:    registry,
	}
}

// RegisterCollector 注册 Prometheus 收集器
func (s *MetricsServer) RegisterCollector(c prometheus.Collector) error {
	return s.registry.Register(c)
}

// MustRegisterCollector 注册收集器（失败时 panic）
func (s *MetricsServer) MustRegisterCollector(c prometheus.Collector) {
	s.registry.MustRegister(c)
}

// SetHealthCheck 设置健康检查函数
func (s *MetricsServer) SetHealthCheck(fn func() HealthStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthCheck = fn
}

// Start 启动服务器
func (s *MetricsServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// 健康检查端点
	mux.HandleFunc(s.healthPath, s.handleHealth)
	mux.HandleFunc(s.healthPath+"/live", s.handleLiveness)
	mux.HandleFunc(s.healthPath+"/ready", s.handleReadiness)

	// Prometheus metrics 端点
	mux.Handle(s.metricsPath, promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
		Registry:          s.registry,
	}))

	// pprof 调试端点
	if s.enablePprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	s.httpServer = &http.Server{
		Addr:         s.listen,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("[Metrics] 服务器错误: %v\n", err)
		}
	}()

	return nil
}

// handleHealth 健康检查处理
func (s *MetricsServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	healthCheck := s.healthCheck
	s.mu.RUnlock()

	var status HealthStatus
	if healthCheck != nil {
		status = healthCheck()
	} else {
		status = HealthStatus{
			Status:    "healthy",
			Timestamp: time.Now(),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if status.Status != "healthy" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(status)
}

// handleLiveness 存活探针
func (s *MetricsServer) handleLiveness(w http.ResponseWriter, r *http.Request) {
	if atomic.LoadInt32(&s.healthy) == 1 {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("NOT OK"))
	}
}

// handleReadiness 就绪探针
func (s *MetricsServer) handleReadiness(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	healthCheck := s.healthCheck
	s.mu.RUnlock()

	if healthCheck != nil {
		status := healthCheck()
		if status.Status == "healthy" || status.Status == "degraded" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("READY"))
			return
		}
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write([]byte("NOT READY"))
}

// SetHealthy 设置健康状态
func (s *MetricsServer) SetHealthy(healthy bool) {
	if healthy {
		atomic.StoreInt32(&s.healthy, 1)
	} else {
		atomic.StoreInt32(&s.healthy, 0)
	}
}

// Stop 停止服务器
func (s *MetricsServer) Stop() {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpServer.Shutdown(ctx)
	}
}

// GetRegistry 获取 registry（用于测试或扩展）
func (s *MetricsServer) GetRegistry() *prometheus.Registry {
	return s.registry
}



