package config

import (
	"encoding/json"
	"os"
	"time"
)

// Lambda送信設定の構造体
type LambdaConfig struct {
	Enabled          bool   `json:"enabled"`
	URL              string `json:"url"`
	APIKey           string `json:"api_key"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
	RetryCount       int    `json:"retry_count"`
	RetryDelaySeconds int    `json:"retry_delay_seconds"`
}

// 送信設定の構造体
type TransmissionConfig struct {
	Lambda               LambdaConfig `json:"lambda"`
	BatchSize            int          `json:"batch_size"`
	FlushIntervalSeconds int          `json:"flush_interval_seconds"`
}

// モジュール設定の構造体
type Config struct {
	Enabled bool                   `json:"enabled"`
	Options map[string]interface{} `json:"options"`
}

// ConfigのJSONの構造体
type Configs struct {
	Transmission TransmissionConfig `json:"transmission"`
	Modules      map[string]Config  `json:"modules"`
}

// 指定されたパスから設定を読み込み
func LoadConfig(path string) (*Configs, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var configs Configs
	if err := json.Unmarshal(file, &configs); err != nil {
		return nil, err
	}

	// デフォルト値を設定
	if configs.Transmission.BatchSize == 0 {
		configs.Transmission.BatchSize = 5
	}
	if configs.Transmission.FlushIntervalSeconds == 0 {
		configs.Transmission.FlushIntervalSeconds = 5
	}
	if configs.Transmission.Lambda.TimeoutSeconds == 0 {
		configs.Transmission.Lambda.TimeoutSeconds = 30
	}
	if configs.Transmission.Lambda.RetryCount == 0 {
		configs.Transmission.Lambda.RetryCount = 3
	}
	if configs.Transmission.Lambda.RetryDelaySeconds == 0 {
		configs.Transmission.Lambda.RetryDelaySeconds = 2
	}

	return &configs, nil
}

// Lambda設定をduration形式に変換
func (c *LambdaConfig) GetTimeout() time.Duration {
	return time.Duration(c.TimeoutSeconds) * time.Second
}

func (c *LambdaConfig) GetRetryDelay() time.Duration {
	return time.Duration(c.RetryDelaySeconds) * time.Second
}

// 送信設定をduration形式に変換
func (c *TransmissionConfig) GetFlushInterval() time.Duration {
	return time.Duration(c.FlushIntervalSeconds) * time.Second
}
