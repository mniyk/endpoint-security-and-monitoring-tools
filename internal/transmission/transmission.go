package transmission

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/mniyk/endpoint-security-and-monitoring-tools/module"
)

const (
	DEFAULT_TIMEOUT       = 30 * time.Second
	DEFAULT_RETRY_COUNT   = 3
	DEFAULT_RETRY_DELAY   = 2 * time.Second
	DEFAULT_FLUSH_TIMEOUT = 5 * time.Second
)

// 実装すべきメソッドを定義
type EventDispatcher interface {
	Add(event module.Event) error
	Flush() error
	IsOverBatchSize() bool
	IsOverTime() bool
}

// Lambda送信設定の構造体
type LambdaConfig struct {
	URL         string
	Enabled     bool
	Timeout     time.Duration
	RetryCount  int
	RetryDelay  time.Duration
	APIKey      string // オプション: 認証用
}

// イベント送信の構造体
type EventSender struct {
	BatchSize    int
	eventQueue   []module.Event
	LastSendTime time.Time
	lambdaConfig *LambdaConfig
	httpClient   *http.Client
	mu           sync.Mutex
}

// 新しいEventSenderを作成（Lambda送信なし）
func NewEventSender(batchSize int) *EventSender {
	return &EventSender{
		BatchSize:    batchSize,
		eventQueue:   make([]module.Event, 0),
		LastSendTime: time.Now(),
		lambdaConfig: nil, // Lambda設定なし（ローカルログのみ）
		httpClient: &http.Client{
			Timeout: DEFAULT_TIMEOUT,
		},
	}
}

// Lambda設定付きでEventSenderを作成
func NewEventSenderWithLambda(batchSize int, config *LambdaConfig) *EventSender {
	if config.Timeout == 0 {
		config.Timeout = DEFAULT_TIMEOUT
	}
	if config.RetryCount == 0 {
		config.RetryCount = DEFAULT_RETRY_COUNT
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = DEFAULT_RETRY_DELAY
	}

	return &EventSender{
		BatchSize:    batchSize,
		eventQueue:   make([]module.Event, 0),
		LastSendTime: time.Now(),
		lambdaConfig: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// イベントをキューに追加
func (s *EventSender) Add(event module.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.eventQueue = append(s.eventQueue, event)

	return nil
}

// 保留中のすべてのイベントを送信
func (s *EventSender) Flush() error {
	s.mu.Lock()
	if len(s.eventQueue) == 0 {
		s.mu.Unlock()
		return nil
	}

	// イベントのコピーを作成
	eventsToSend := make([]module.Event, len(s.eventQueue))
	copy(eventsToSend, s.eventQueue)

	// キューをクリア
	s.eventQueue = make([]module.Event, 0)
	s.LastSendTime = time.Now()
	s.mu.Unlock()

	// Lambda送信が有効な場合
	if s.lambdaConfig != nil && s.lambdaConfig.Enabled {
		return s.sendToLambda(eventsToSend)
	}

	// Lambda送信が無効な場合はローカルログのみ
	return s.logEventsLocally(eventsToSend)
}

// イベントをLambdaに送信
func (s *EventSender) sendToLambda(events []module.Event) error {
	// JSON形式に変換
	jsonData, err := json.Marshal(map[string]interface{}{
		"events":    events,
		"count":     len(events),
		"timestamp": time.Now().Format(time.RFC3339),
	})
	if err != nil {
		log.Printf("[Transmission] Failed to marshal events: %v", err)
		return s.logEventsLocally(events) // フォールバック
	}

	// リトライロジック
	var lastError error
	for attempt := 1; attempt <= s.lambdaConfig.RetryCount; attempt++ {
		err := s.sendHTTPRequest(jsonData)
		if err == nil {
			log.Printf("[Transmission] Successfully sent %d events to Lambda", len(events))
			return nil
		}

		lastError = err
		log.Printf("[Transmission] Attempt %d/%d failed: %v", attempt, s.lambdaConfig.RetryCount, err)

		if attempt < s.lambdaConfig.RetryCount {
			time.Sleep(s.lambdaConfig.RetryDelay * time.Duration(attempt))
		}
	}

	log.Printf("[Transmission] Failed to send events after %d attempts. Logging locally.", s.lambdaConfig.RetryCount)
	s.logEventsLocally(events) // フォールバック

	return fmt.Errorf("failed to send events to Lambda after %d attempts: %w", s.lambdaConfig.RetryCount, lastError)
}

// HTTPリクエストを送信
func (s *EventSender) sendHTTPRequest(jsonData []byte) error {
	req, err := http.NewRequest("POST", s.lambdaConfig.URL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// APIキーが設定されている場合は追加
	if s.lambdaConfig.APIKey != "" {
		req.Header.Set("X-API-Key", s.lambdaConfig.APIKey)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// レスポンスボディを読み取り
	body, _ := io.ReadAll(resp.Body)

	// ステータスコードをチェック
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Lambda returned status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("[Transmission] Lambda response: %s", string(body))
	return nil
}

// イベントをローカルにログ出力
func (s *EventSender) logEventsLocally(events []module.Event) error {
	log.Printf("[Transmission] Logging %d events locally", len(events))

	for _, event := range events {
		jsonData, err := json.MarshalIndent(event, "", "  ")
		if err == nil {
			log.Printf("[Transmission] Event: %s", string(jsonData))
		}
	}

	return nil
}

// バッチサイズを超えたかどうかを確認
func (s *EventSender) IsOverBatchSize() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.eventQueue) >= s.BatchSize
}

// 最後の送信から一定時間経過したかどうかを確認
func (s *EventSender) IsOverTime() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return time.Since(s.LastSendTime) > DEFAULT_FLUSH_TIMEOUT
}
