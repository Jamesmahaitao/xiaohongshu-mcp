package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// authMiddleware 静态 Bearer Token 鉴权中间件，Token 为空时关闭鉴权。
func authMiddleware(token string) gin.HandlerFunc {
	expectedToken := []byte(token)

	return func(c *gin.Context) {
		if token == "" {
			c.Next()
			return
		}

		scheme, credentials, found := strings.Cut(c.GetHeader("Authorization"), " ")
		credentials = strings.TrimLeft(credentials, " ")
		if !found || !strings.EqualFold(scheme, "Bearer") ||
			subtle.ConstantTimeCompare([]byte(credentials), expectedToken) != 1 {
			c.Header("WWW-Authenticate", "Bearer")
			respondError(c, http.StatusUnauthorized, "UNAUTHORIZED", "未授权", nil)
			c.Abort()
			return
		}

		c.Next()
	}
}

// corsMiddleware CORS 中间件
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// errorHandlingMiddleware 错误处理中间件
func errorHandlingMiddleware() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered any) {
		logrus.Errorf("服务器内部错误: %v, path: %s", recovered, c.Request.URL.Path)

		respondError(c, http.StatusInternalServerError, "INTERNAL_ERROR",
			"服务器内部错误", recovered)
	})
}

// mcpMethodLogger 从 JSON-RPC 请求体中提取 method 字段，
// 并在请求结束时将 method、路径、状态码、耗时合并到一行日志。
// 替换了默认 gin.Logger()，避免日志分散在多行。
func mcpMethodLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		var mcpMethod string

		// 读取请求体，解析 method（只在有 body 时才读）
		if c.Request.ContentLength > 0 && c.Request.Body != nil {
			var buf []byte
			if bs, err := io.ReadAll(c.Request.Body); err == nil {
				buf = bs
				c.Request.Body = io.NopCloser(bytes.NewBuffer(buf))
				mcpMethod = extractMCPMethod(buf)
			}
		}

		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// 处理请求
		c.Next()

		// 请求结束，打印一行合并日志
		latency := time.Since(start)
		status := c.Writer.Status()
		clientIP := c.ClientIP()
		method := c.Request.Method

		if raw != "" {
			path = path + "?" + raw
		}

		entry := logrus.WithFields(logrus.Fields{
			"status":    status,
			"latency":   latency.String(),
			"clientIP":  clientIP,
			"method":    method,
			"path":      path,
			"mcpMethod": mcpMethod,
		})

		if len(c.Errors) > 0 {
			entry.Error(c.Errors.String())
		} else {
			// 耗时保留小数点后两位，统一精度
			latencyMs := float64(latency.Nanoseconds()) / 1e6
			logrus.Infof("[GIN] %3d | %9.2fms | %15s | %-6s %s | mcp=%s",
				status, latencyMs, clientIP, method, path, mcpMethod)
		}
	}
}

// extractMCPMethod 从 JSON-RPC 请求体中提取方法名。
// 优先取 params.name（工具调用），其次取顶层 method（握手/通知等）。
func extractMCPMethod(body []byte) string {
	// 快速判断第一个非空字符
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return ""
	}

	// 批量请求 [...]
	if trimmed[0] == '[' {
		var batch []map[string]any
		if err := json.Unmarshal(body, &batch); err != nil || len(batch) == 0 {
			return ""
		}
		first := batch[0]
		if params, ok := first["params"].(map[string]any); ok {
			if name, ok := params["name"].(string); ok {
				return name
			}
		}
		if m, ok := first["method"].(string); ok {
			return m
		}
		return ""
	}

	// 单请求 { ... }
	var req struct {
		Method string         `json:"method"`
		Params map[string]any `json:"params"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	// 工具调用 params.name 优先级最高
	if req.Params != nil {
		if name, ok := req.Params["name"].(string); ok {
			return name
		}
	}
	return req.Method
}
