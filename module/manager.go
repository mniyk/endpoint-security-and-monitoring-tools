package module

import (
	"fmt"
	"sync"

	"github.com/mniyk/endpoint-security-and-monitoring-tools/internal/config"
)

// モジュール管理の構造体
type Manager struct {
	Modules       map[string]Module
	activeModules map[string]bool
	configs       *config.Configs
	mu            sync.RWMutex
}

// 新しいManagerを作成
func NewManager(configs *config.Configs) *Manager {
	return &Manager{
		Modules:       make(map[string]Module),
		activeModules: make(map[string]bool),
		configs:       configs,
	}
}

// モジュールを登録
func (m *Manager) RegisterModule(name string, module Module) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.Modules[name]; exists {
		return fmt.Errorf("module %s already registered", name)
	}

	m.Modules[name] = module
	return nil
}

// すべてのモジュールを初期化
func (m *Manager) InitializeAllModules() map[string]error {
	errors := make(map[string]error)

	m.mu.Lock()
	defer m.mu.Unlock()

	for name, module := range m.Modules {
		if moduleConfig, ok := m.configs.Modules[name]; ok && moduleConfig.Enabled {
			err := module.Initialize()
			if err != nil {
				errors[name] = err
				continue
			}
			m.activeModules[name] = true
		}
	}

	return errors
}

// すべてのモジュールを開始
func (m *Manager) StartAllModules() map[string]error {
	errors := make(map[string]error)

	m.mu.RLock()
	defer m.mu.RUnlock()

	for name, active := range m.activeModules {
		if active {
			module := m.Modules[name]
			err := module.Start()
			if err != nil {
				errors[name] = err
			}
		}
	}

	return errors
}

// すべてのアクティブなモジュールを停止
func (m *Manager) StopAllModules() map[string]error {
	errors := make(map[string]error)

	m.mu.RLock()
	modules := make(map[string]Module)

	for name, active := range m.activeModules {
		if active {
			modules[name] = m.Modules[name]
		}
	}
	m.mu.RUnlock()

	for name, module := range modules {
		err := module.Stop()
		if err != nil {
			errors[name] = err
		}

		m.mu.Lock()
		m.activeModules[name] = false
		m.mu.Unlock()
	}

	return errors
}
