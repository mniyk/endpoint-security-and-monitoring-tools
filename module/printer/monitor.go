package printer

import (
	"fmt"
	"log"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/mniyk/endpoint-security-and-monitoring-tools/internal/config"
	"github.com/mniyk/endpoint-security-and-monitoring-tools/internal/transmission"
	"github.com/mniyk/endpoint-security-and-monitoring-tools/internal/userinfo"
	"github.com/mniyk/endpoint-security-and-monitoring-tools/module"
)

const (
	MONITOR_INTERVAL           = 2 * time.Second
	MODULE_NAME                = "Printer Transfer Monitoring"
	PRINT_JOB_STARTED_SEVERITY = 5
)

// Windows API用の関数
var (
	winspool = windows.NewLazySystemDLL("winspool.drv")

	procEnumJobsW     = winspool.NewProc("EnumJobsW")
	procOpenPrinterW  = winspool.NewProc("OpenPrinterW")
	procClosePrinter  = winspool.NewProc("ClosePrinter")
	procEnumPrintersW = winspool.NewProc("EnumPrintersW")
)

// PRINTER_INFO_2 structure for Windows API
type PRINTER_INFO_2 struct {
	ServerName         *uint16
	PrinterName        *uint16
	ShareName          *uint16
	PortName           *uint16
	DriverName         *uint16
	Comment            *uint16
	Location           *uint16
	DevMode            uintptr
	SepFile            *uint16
	PrintProcessor     *uint16
	Datatype           *uint16
	Parameters         *uint16
	SecurityDescriptor uintptr
	Attributes         uint32
	Priority           uint32
	DefaultPriority    uint32
	StartTime          uint32
	UntilTime          uint32
	Status             uint32
	JobsCount          uint32
	AveragePPM         uint32
}

// JOB_INFO_2 structure for Windows API
type JOB_INFO_2 struct {
	JobId              uint32
	PrinterName        *uint16
	MachineName        *uint16
	UserName           *uint16
	Document           *uint16
	NotifyName         *uint16
	DataType           *uint16
	PrintProcessor     *uint16
	Parameters         *uint16
	DriverName         *uint16
	DevMode            uintptr
	Status             uint32
	SecurityDescriptor uintptr
	StatusString       *uint16
	Priority           uint32
	Position           uint32
	StartTime          uint32
	UntilTime          uint32
	TotalPages         uint32
	Size               uint32
	Submitted          windows.Filetime
	Time               uint32
	PagesPrinted       uint32
}

// 印刷操作情報の構造体
type PrintOperation struct {
	JobID        uint32
	PrinterName  string
	DocumentName string
	UserName     string
	Pages        uint32
	Copies       uint32
	Timestamp    time.Time
	UserInfo     *userinfo.UserInfo
}

// Print Monitoringの設定の構造体
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
	lastJobID       uint32
	userInfo        *userinfo.UserInfo
	eventDispatcher transmission.EventDispatcher
}

// 新しいMonitorを作成
func NewMonitor(config *MonitorConfig, userInfo *userinfo.UserInfo, eventDispatcher transmission.EventDispatcher) *Monitor {
	return &Monitor{
		config:          *config,
		events:          make([]module.Event, 0),
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

	// 印刷監視を開始
	go m.startPrintMonitoring()

	return nil
}

// 監視の継続的なループを実行
func (m *Monitor) startPrintMonitoring() {
	for {
		select {
		case <-m.stopChan:
			return
		default:
			// 印刷ジョブをスキャン
			m.checkPrintJobs()

			// 設定された間隔で再スキャン
			time.Sleep(MONITOR_INTERVAL)
		}
	}
}

// 印刷ジョブをチェック
func (m *Monitor) checkPrintJobs() {
	printers := m.getLocalPrinters()

	for _, printerName := range printers {
		jobs := m.getPrintJobs(printerName)

		for _, job := range jobs {
			if job.JobId > m.lastJobID {
				m.lastJobID = job.JobId
				m.processPrintJob(job)
			}
		}
	}
}

// ローカルプリンターリストを取得
func (m *Monitor) getLocalPrinters() []string {
	var printers []string

	// EnumPrintersW API を使用してプリンターを取得
	var bytesNeeded, printerCount uint32

	// 最初の呼び出しで必要なバッファサイズを取得
	_, _, _ = procEnumPrintersW.Call(
		2,    // PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS
		0,    // pName (local machine)
		2,    // Level 2 (PRINTER_INFO_2)
		0, 0, // pPrinterEnum, cbBuf
		uintptr(unsafe.Pointer(&bytesNeeded)),
		uintptr(unsafe.Pointer(&printerCount)),
	)

	if bytesNeeded > 0 {
		// 必要なサイズのバッファを確保
		buffer := make([]byte, bytesNeeded)
		ret, _, _ := procEnumPrintersW.Call(
			2,
			0,
			2,
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(bytesNeeded),
			uintptr(unsafe.Pointer(&bytesNeeded)),
			uintptr(unsafe.Pointer(&printerCount)),
		)

		if ret != 0 && printerCount > 0 {
			// PRINTER_INFO_2構造体を解析
			printerInfoSize := unsafe.Sizeof(PRINTER_INFO_2{})

			for i := uint32(0); i < printerCount; i++ {
				offset := uintptr(i) * printerInfoSize
				printerInfo := (*PRINTER_INFO_2)(unsafe.Pointer(uintptr(unsafe.Pointer(&buffer[0])) + offset))

				if printerInfo.PrinterName != nil {
					printerName := windows.UTF16PtrToString(printerInfo.PrinterName)
					if printerName != "" {
						printers = append(printers, printerName)
					}
				}
			}
		}
	}

	// プリンターが見つからない場合は異常終了
	if len(printers) == 0 {
		log.Fatalf("[%s] Failed to enumerate printers: no printers found", MODULE_NAME)
	}

	return printers
}

// 指定プリンターの印刷ジョブを取得
func (m *Monitor) getPrintJobs(printerName string) []JOB_INFO_2 {
	var jobs []JOB_INFO_2

	printerNamePtr, _ := windows.UTF16PtrFromString(printerName)
	var handle windows.Handle

	// プリンターを開く
	ret, _, _ := procOpenPrinterW.Call(
		uintptr(unsafe.Pointer(printerNamePtr)),
		uintptr(unsafe.Pointer(&handle)),
		0,
	)

	if ret == 0 {
		return jobs
	}
	defer procClosePrinter.Call(uintptr(handle))

	// ジョブを列挙
	var bytesNeeded, jobCount uint32

	procEnumJobsW.Call(
		uintptr(handle),
		0, 0xFFFFFFFF,
		2,
		0, 0,
		uintptr(unsafe.Pointer(&bytesNeeded)),
		uintptr(unsafe.Pointer(&jobCount)),
	)

	if bytesNeeded > 0 {
		buffer := make([]byte, bytesNeeded)
		ret, _, _ := procEnumJobsW.Call(
			uintptr(handle),
			0, 0xFFFFFFFF,
			2,
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(bytesNeeded),
			uintptr(unsafe.Pointer(&bytesNeeded)),
			uintptr(unsafe.Pointer(&jobCount)),
		)

		if ret != 0 && jobCount > 0 {
			jobSize := unsafe.Sizeof(JOB_INFO_2{})
			for i := uint32(0); i < jobCount; i++ {
				offset := uintptr(i) * jobSize
				job := (*JOB_INFO_2)(unsafe.Pointer(uintptr(unsafe.Pointer(&buffer[0])) + offset))
				jobs = append(jobs, *job)
			}
		}
	}

	return jobs
}

// 印刷ジョブを処理
func (m *Monitor) processPrintJob(job JOB_INFO_2) {
	operation := PrintOperation{
		JobID:        job.JobId,
		PrinterName:  windows.UTF16PtrToString(job.PrinterName),
		DocumentName: windows.UTF16PtrToString(job.Document),
		UserName:     windows.UTF16PtrToString(job.UserName),
		Pages:        job.TotalPages,
		Timestamp:    time.Now(),
		UserInfo:     m.userInfo,
	}

	m.logPrintOperation(operation)
}

// 印刷操作をログ記録
func (m *Monitor) logPrintOperation(op PrintOperation) {
	log.Printf(
		"[%s] PRINT JOB User: %s Host: %s JobID: %d Printer: %s Document: %s Pages: %d Time: %s\n",
		MODULE_NAME,
		op.UserInfo.UserName,
		op.UserInfo.HostName,
		op.JobID,
		op.PrinterName,
		op.DocumentName,
		op.Pages,
		op.Timestamp.Format("2006-01-02 15:04:05"),
	)

	m.addEvent(
		"print_job_started",
		PRINT_JOB_STARTED_SEVERITY,
		map[string]interface{}{
			"job_id":       op.JobID,
			"printer_name": op.PrinterName,
			"document":     op.DocumentName,
			"user":         op.UserInfo.UserName,
			"host":         op.UserInfo.HostName,
			"pages":        op.Pages,
			"timestamp":    op.Timestamp.Format(time.RFC3339),
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

	eventsCopy := make([]module.Event, len(m.events))
	copy(eventsCopy, m.events)

	return eventsCopy
}

// 新しいイベントを追加
func (m *Monitor) addEvent(eventType string, severity int, data map[string]interface{}) {
	event := module.Event{
		ID:        fmt.Sprintf("print-%d", time.Now().UnixNano()),
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
