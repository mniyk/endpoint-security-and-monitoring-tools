package bluetooth

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/mniyk/endpoint-security-and-monitoring-tools/internal/config"
	"github.com/mniyk/endpoint-security-and-monitoring-tools/internal/transmission"
	"github.com/mniyk/endpoint-security-and-monitoring-tools/internal/userinfo"
	"github.com/mniyk/endpoint-security-and-monitoring-tools/module"
)

const (
	MONITOR_INTERVAL            = 5 * time.Second
	MODULE_NAME                 = "Bluetooth File Transfer Monitoring"
	BLUETOOTH_TRANSFER_SEVERITY = 5
)

// Bluetooth File Transfer Monitoringの設定の構造体
type MonitorConfig struct {
	EnableBluetooth bool `json:"enable_bluetooth"`
}

// 新しいMonitorConfigを作成
func NewMonitorConfig(moduleConfig config.Config) *MonitorConfig {
	return &MonitorConfig{
		EnableBluetooth: true,
	}
}

// ファイル転送情報
type FileTransfer struct {
	Protocol   string // "bluetooth_obex"
	DeviceName string
	FileName   string
	FileSize   int64
	Direction  string // "outbound"（送信のみ）
	Status     string // "active"
	StartTime  time.Time
}

// 監視のための構造体
type Monitor struct {
	events          []module.Event
	config          MonitorConfig
	stopChan        chan struct{}
	eventsMu        sync.RWMutex
	activeTransfers map[string]time.Time // 重複検出防止用
	userInfo        *userinfo.UserInfo
	eventDispatcher transmission.EventDispatcher
}

// 新しいMonitorを作成
func NewMonitor(config *MonitorConfig, userInfo *userinfo.UserInfo, eventDispatcher transmission.EventDispatcher) *Monitor {
	return &Monitor{
		config:          *config,
		events:          make([]module.Event, 0),
		activeTransfers: make(map[string]time.Time),
		userInfo:        userInfo,
		eventDispatcher: eventDispatcher,
	}
}

// モジュールを初期化
func (m *Monitor) Initialize() error {
	m.stopChan = make(chan struct{})
	log.Printf("[%s] Initialize...", MODULE_NAME)
	return nil
}

// モニタリングを開始
func (m *Monitor) Start() error {
	log.Printf("[%s] Start...", MODULE_NAME)

	// Bluetooth ファイル転送監視を開始
	if m.config.EnableBluetooth {
		go m.startBluetoothFileTransferMonitoring()
		log.Printf("[%s] Started Bluetooth file transfer monitoring", MODULE_NAME)
	}

	return nil
}

// Bluetooth ファイル転送監視を開始
func (m *Monitor) startBluetoothFileTransferMonitoring() {
	for {
		select {
		case <-m.stopChan:
			return
		default:
			// Bluetoothファイル転送を検出
			transfers := m.detectBluetoothFileTransfers()
			for _, transfer := range transfers {
				m.logFileTransfer(transfer)
			}

			time.Sleep(MONITOR_INTERVAL)
		}
	}
}

// Bluetoothファイル転送を検出（送信のみ）
func (m *Monitor) detectBluetoothFileTransfers() []FileTransfer {
	var transfers []FileTransfer

	// Bluetoothファイル転送ウィザード（fsquirt.exe）を監視
	cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq fsquirt.exe", "/FO", "CSV")
	output, err := cmd.Output()
	if err == nil && strings.Contains(string(output), "fsquirt.exe") {
		// 重複検出防止
		transferKey := "bluetooth_fsquirt"
		if lastDetected, exists := m.activeTransfers[transferKey]; exists {
			if time.Since(lastDetected) < 30*time.Second {
				return transfers
			}
		}

		m.activeTransfers[transferKey] = time.Now()

		transfer := FileTransfer{
			Protocol:   "bluetooth_obex",
			DeviceName: "Bluetooth Device",
			FileName:   "Bluetooth File Transfer",
			Direction:  "outbound",
			Status:     "active",
			StartTime:  time.Now(),
		}
		transfers = append(transfers, transfer)
	} else {
		delete(m.activeTransfers, "bluetooth_fsquirt")
	}

	return transfers
}

// ファイル転送を記録
func (m *Monitor) logFileTransfer(transfer FileTransfer) {
	log.Printf(
		"[%s] File transfer detected - Protocol: %s Device: %s File: %s Direction: %s Status: %s",
		MODULE_NAME,
		transfer.Protocol,
		transfer.DeviceName,
		transfer.FileName,
		transfer.Direction,
		transfer.Status,
	)

	m.addEvent(
		"bluetooth_file_transfer",
		BLUETOOTH_TRANSFER_SEVERITY,
		map[string]interface{}{
			"protocol":    transfer.Protocol,
			"device_name": transfer.DeviceName,
			"file_name":   transfer.FileName,
			"file_size":   transfer.FileSize,
			"direction":   transfer.Direction,
			"status":      transfer.Status,
			"user":        m.userInfo.UserName,
			"host":        m.userInfo.HostName,
			"timestamp":   transfer.StartTime.Format(time.RFC3339),
		},
	)
}

// モニタリングを停止
func (m *Monitor) Stop() error {
	log.Printf("[%s] Stop...", MODULE_NAME)
	close(m.stopChan)
	return nil
}

// モジュールが検出したイベントを取得
func (m *Monitor) GetEvents() []module.Event {
	m.eventsMu.RLock()
	defer m.eventsMu.RUnlock()

	// イベントのコピーを返す（オリジナルが変更されないように）
	eventsCopy := make([]module.Event, len(m.events))
	copy(eventsCopy, m.events)

	return eventsCopy
}

// 新しいイベントを追加
func (m *Monitor) addEvent(eventType string, severity int, data map[string]interface{}) {
	event := module.Event{
		ID:        fmt.Sprintf("wireless-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		Type:      eventType,
		Severity:  severity,
		Data:      data,
	}

	m.eventsMu.Lock()
	m.events = append(m.events, event)
	m.eventsMu.Unlock()

	log.Printf("[%s] Detection new event: %s Importance: %d", MODULE_NAME, eventType, severity)

	// イベントをdispatcherに送信（非同期）
	go m.eventDispatcher.Add(event)
}
