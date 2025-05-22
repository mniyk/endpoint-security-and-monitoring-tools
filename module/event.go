package module

import "time"

// イベントの構造体
type Event struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Type      string                 `json:"type"`
	Severity  int                    `json:"severity"` // 1-5 (低-高)
	Data      map[string]interface{} `json:"data"`
}
