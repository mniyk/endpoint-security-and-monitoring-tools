package config

import (
	"encoding/json"
	"os"
)

// モジュール設定の構造体
type Config struct {
	Enabled bool                   `json:"enabled"`
	Options map[string]interface{} `json:"options"`
}

// ConfigのJSONの構造体
type Configs struct {
	Modules map[string]Config `json:"modules"`
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

	return &configs, nil
}
