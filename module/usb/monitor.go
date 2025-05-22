package usb

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/sys/windows"

	"github.com/mniyk/endpoint-security-and-monitoring-tools/internal/config"
	"github.com/mniyk/endpoint-security-and-monitoring-tools/internal/transmission"
	"github.com/mniyk/endpoint-security-and-monitoring-tools/internal/userinfo"
	"github.com/mniyk/endpoint-security-and-monitoring-tools/module"
)

const (
	MONITOR_INTERVAL            = 5 * time.Second
	DRIVE_REMOVABLE             = 2
	MAX_WATCH_DEPTH             = 10
	MODULE_NAME                 = "USB File Transfer Monitoring"
	CONNECTED_DRIVE_SEVERITY    = 5
	DISCONNECTED_DRIVE_SEVERITY = 5
	FILE_OPERATION_SEVERITY     = 5
)

// Windows API用の関数
var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procGetLogicalDrives = kernel32.NewProc("GetLogicalDrives")
	procGetDriveType     = kernel32.NewProc("GetDriveTypeW")
)

// ファイル操作情報の構造体
type FileOperation struct {
	Operation   string
	FilePath    string
	FileName    string
	DriveLetter string
	UserInfo    *userinfo.UserInfo
	Timestamp   time.Time
	FileSize    int64
}

// USB File Transfer Monitoringの設定の構造体
type MonitorConfig struct {
}

// 新しいMonitorConfigを作成
func NewMonitorConfig(moduleConfig config.Config) *MonitorConfig {
	return &MonitorConfig{}
}

// 監視のための構造体
type Monitor struct {
	events          []module.Event
	config          MonitorConfig
	stopChan        chan struct{}
	eventsMu        sync.RWMutex
	connectedDrives map[string]bool
	watchContexts   map[string]context.CancelFunc
	userInfo        *userinfo.UserInfo
	eventDispatcher transmission.EventDispatcher
}

// 新しいMonitorを作成
func NewMonitor(config *MonitorConfig, userInfo *userinfo.UserInfo, eventDispatcher transmission.EventDispatcher) *Monitor {
	return &Monitor{
		config:          *config,
		events:          make([]module.Event, 0),
		connectedDrives: make(map[string]bool),
		watchContexts:   make(map[string]context.CancelFunc),
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

	// ドライブ監視を開始
	go m.startDriveMonitoring()

	return nil
}

// 監視の継続的なループを実行
func (m *Monitor) startDriveMonitoring() {
	for {
		select {
		case <-m.stopChan:
			return
		default:
			// リムーバブルドライブをスキャン
			drives := m.getAvailableDrives()
			currentDrives, updatedConnectedDrives := m.detectConnectedDrives(drives)
			m.connectedDrives = m.detectDisconnectedDrives(currentDrives, updatedConnectedDrives)

			// 設定された間隔で再スキャン
			time.Sleep(MONITOR_INTERVAL)
		}
	}
}

// 利用可能なドライブレターを取得
func (m *Monitor) getAvailableDrives() []string {
	var drives []string

	// GetLogicalDrives Win32 API呼び出し
	bitmask, _, err := procGetLogicalDrives.Call()

	if bitmask == 0 {
		fmt.Printf("[%s] Failed getting logical drives: %v\n", MODULE_NAME, err)
		return drives
	}

	// 各ビットをチェック (A-Z)
	for i := 0; i < 26; i++ {
		if (bitmask & (1 << uint(i))) != 0 {
			drives = append(drives, string(rune('A'+i)))
		}
	}

	return drives
}

// 接続されているリムーバブルドライブを検出
func (m *Monitor) detectConnectedDrives(drives []string) (map[string]bool, map[string]bool) {
	currentDrives := make(map[string]bool)
	newConnectedDrives := make(map[string]bool)

	// 既存の接続を引き継ぐ
	for k, v := range m.connectedDrives {
		newConnectedDrives[k] = v
	}

	// 各ドライブをチェック
	for _, driveLetter := range drives {
		drivePath := fmt.Sprintf("%s:\\", driveLetter)

		// リムーバブルドライブかチェック
		if m.isRemovableDrive(drivePath) {
			currentDrives[driveLetter] = true

			// 新しいドライブを検出
			if _, exists := m.connectedDrives[driveLetter]; !exists {
				log.Printf("[%s] Connected drive(%s)\n", MODULE_NAME, driveLetter)

				// イベントを生成
				m.addEvent(
					"connected_drive",
					CONNECTED_DRIVE_SEVERITY,
					map[string]interface{}{
						"drive": driveLetter,
						"user":  m.userInfo.UserName,
						"host":  m.userInfo.HostName,
					},
				)

				// 接続を記録
				newConnectedDrives[driveLetter] = true

				// ファイル監視を開始
				go m.monitorDriveFiles(driveLetter)
			}
		}
	}

	return currentDrives, newConnectedDrives
}

// リムーバブルドライブかどうかをチェック
func (m *Monitor) isRemovableDrive(drivePath string) bool {
	drivePathUTF16, err := syscall.UTF16PtrFromString(drivePath)
	if err != nil {
		fmt.Printf("[%s] Failed converting drive path to UTF16: %v\n", MODULE_NAME, err)
		return false
	}

	// GetDriveType Win32 API呼び出し
	driveType, _, _ := procGetDriveType.Call(uintptr(unsafe.Pointer(drivePathUTF16)))

	return driveType == DRIVE_REMOVABLE
}

// ドライブのファイル操作を監視
func (m *Monitor) monitorDriveFiles(driveLetter string) {
	// 監視用のキャンセル可能なコンテキストを作成
	ctx, cancel := context.WithCancel(context.Background())
	m.watchContexts[driveLetter] = cancel

	drivePath := fmt.Sprintf("%s:\\", driveLetter)
	log.Printf("[%s] Starting file monitoring for drive(%s)\n", MODULE_NAME, driveLetter)

	// ファイル監視を設定
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("[%s] Failed creating file watcher: %v\n", MODULE_NAME, err)
		delete(m.watchContexts, driveLetter)
		return
	}

	// 再帰的にディレクトリ監視を追加 (深さ制限付き)
	m.addDirectoriesToWatch(watcher, drivePath, MAX_WATCH_DEPTH)

	// イベント監視ループを開始
	go func() {
		// 関数終了時にリソースをクリーンアップ
		defer func() {
			watcher.Close()
			log.Printf("[%s] Stopped file monitoring for drive(%s)\n", MODULE_NAME, driveLetter)
		}()

		m.processFileEvents(ctx, watcher, driveLetter)
	}()
}

// ドライブ内のすべてのディレクトリを再帰的に監視対象に追加
func (m *Monitor) addDirectoriesToWatch(watcher *fsnotify.Watcher, rootPath string, maxDepth int) {
	var walkFn filepath.WalkFunc = func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// AccessDenied や NotFound などのエラーはスキップ
			return nil
		}

		if info != nil && info.IsDir() {
			// 監視深さの制限をチェック
			if maxDepth > 0 {
				// 相対パスを取得して深さを計算
				relPath, err := filepath.Rel(rootPath, path)
				if err == nil && relPath != "" && relPath != "." {
					depth := len(strings.Split(relPath, string(os.PathSeparator)))
					if depth > maxDepth {
						return filepath.SkipDir
					}
				}
			}

			// ディレクトリを監視対象に追加
			err = watcher.Add(path)
			if err != nil {
				log.Printf("[%s] Failed watching directory %s: %v\n", MODULE_NAME, path, err)
			}
		}
		return nil
	}

	err := filepath.Walk(rootPath, walkFn)
	if err != nil {
		log.Printf("[%s] Failed walking directory tree: %v\n", MODULE_NAME, err)
	}
}

// ファイルシステムイベントを処理するループを実行
func (m *Monitor) processFileEvents(ctx context.Context, watcher *fsnotify.Watcher, driveLetter string) {
	for {
		select {
		case <-ctx.Done():
			// コンテキストがキャンセルされた場合は終了
			return

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			// CreateとWrite操作のみを処理
			if event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Write == fsnotify.Write {
				filePath := event.Name

				// ディレクトリの場合は監視対象に追加して、イベント処理はスキップ
				fileInfo, err := os.Stat(filePath)
				if err == nil && fileInfo.IsDir() {
					watcher.Add(filePath)
					continue
				}

				// ファイル操作情報を作成
				fileName := filepath.Base(filePath)
				operation := FileOperation{
					Operation:   m.getOperationName(event.Op),
					FilePath:    filePath,
					FileName:    fileName,
					DriveLetter: driveLetter,
					UserInfo:    m.userInfo,
					Timestamp:   time.Now(),
					FileSize:    0,
				}

				// ファイルサイズを取得
				if fileInfo, err := os.Stat(filePath); err == nil && !fileInfo.IsDir() {
					operation.FileSize = fileInfo.Size()
				}

				// ファイル操作を記録
				m.logFileOperation(operation)
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("[%s] Failed watcher: %v\n", MODULE_NAME, err)
		}
	}
}

// イベント操作名を取得
func (m *Monitor) getOperationName(op fsnotify.Op) string {
	switch {
	case op&fsnotify.Create == fsnotify.Create:
		return "create"
	case op&fsnotify.Write == fsnotify.Write:
		return "write"
	case op&fsnotify.Remove == fsnotify.Remove:
		return "delete"
	case op&fsnotify.Rename == fsnotify.Rename:
		return "rename"
	case op&fsnotify.Chmod == fsnotify.Chmod:
		return "chmod"
	default:
		return "unknown"
	}
}

// ファイル操作を記録するメソッド
func (m *Monitor) logFileOperation(op FileOperation) {
	// コンソールに出力
	log.Printf(
		"[%s] Operation: %s User: %s Host: %s Drive: %s Path: %s File: %s Size: %d Time: %s\n",
		MODULE_NAME,
		strings.ToUpper(op.Operation),
		op.UserInfo.UserName,
		op.UserInfo.HostName,
		op.DriveLetter,
		op.FilePath,
		op.FileName,
		op.FileSize,
		op.Timestamp.Format("2006-01-02 15:04:05"),
	)

	// モジュールのイベントとして追加
	m.addEvent(
		"file_"+op.Operation,
		FILE_OPERATION_SEVERITY,
		map[string]interface{}{
			"path":      op.FilePath,
			"filename":  op.FileName,
			"drive":     op.DriveLetter,
			"user":      op.UserInfo.UserName,
			"host":      op.UserInfo.HostName,
			"timestamp": op.Timestamp.Format(time.RFC3339),
			"operation": op.Operation,
			"size":      op.FileSize,
		},
	)
}

// 切断されたドライブを検出
func (m *Monitor) detectDisconnectedDrives(currentDrives map[string]bool, connectedDrives map[string]bool) map[string]bool {
	// 新しいマップを作成（元のマップを変更しないため）
	updatedDrives := make(map[string]bool)
	for k, v := range connectedDrives {
		updatedDrives[k] = v
	}

	// 切断されたドライブを検出
	for driveLetter := range connectedDrives {
		if _, exists := currentDrives[driveLetter]; !exists {
			log.Printf("[%s] Disconnected drive(%s)\n", MODULE_NAME, driveLetter)

			// イベントを生成
			m.addEvent(
				"disconnected_drive",
				DISCONNECTED_DRIVE_SEVERITY,
				map[string]interface{}{
					"drive": driveLetter,
					"user":  m.userInfo.UserName,
					"host":  m.userInfo.HostName,
				},
			)

			// 関連するゴルーチンを終了させる
			if cancel, ok := m.watchContexts[driveLetter]; ok {
				cancel()
				delete(m.watchContexts, driveLetter)
			}

			// 更新後のマップから削除
			delete(updatedDrives, driveLetter)
		}
	}

	return updatedDrives
}

// モニタリングを停止
func (m *Monitor) Stop() error {
	log.Printf("[%s] Stop...", MODULE_NAME)

	// すべての監視コンテキストを終了
	for _, cancel := range m.watchContexts {
		cancel()
	}

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
		ID:        fmt.Sprintf("usb-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		Type:      eventType,
		Severity:  severity,
		Data:      data,
	}

	m.eventsMu.Lock()
	m.events = append(m.events, event)
	m.eventsMu.Unlock()

	log.Printf("[%s] Detection new event: %s Importance: %d\n", MODULE_NAME, eventType, severity)

	// イベントをsenderに送信（非同期）
	go m.eventDispatcher.Add(event)
}
