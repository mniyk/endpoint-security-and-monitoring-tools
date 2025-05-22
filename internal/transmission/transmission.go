package transmission

import (
	"encoding/json"
	"log"
	"time"

	"github.com/mniyk/endpoint-security-and-monitoring-tools/module"
)

// 実装すべきメソッドを定義
type EventDispatcher interface {
	Add(event module.Event) error
	Flush() error
	IsOverBatchSize() bool
	IsOverTime() bool
}

// イベント送信の構造体
type EventSender struct {
	BatchSize    int
	eventQueue   []module.Event
	LastSendTime time.Time
}

// 新しいEventSenderを作成
func NewEventSender(batchSize int) *EventSender {
	return &EventSender{
		BatchSize:    batchSize,
		eventQueue:   make([]module.Event, 0),
		LastSendTime: time.Now(),
	}
}

// イベントをキューに追加
func (s *EventSender) Add(event module.Event) error {
	s.eventQueue = append(s.eventQueue, event)

	return nil
}

// 保留中のすべてのイベントを送信
func (s *EventSender) Flush() error {
	if len(s.eventQueue) == 0 {
		return nil
	}

	// イベントをJSON形式に変換して送信の様子を表示
	for _, event := range s.eventQueue {
		jsonData, err := json.MarshalIndent(event, "", "  ")
		if err == nil {
			log.Printf("[Transmission] Send event: %s\n", string(jsonData))
		}
	}

	// 送信済みイベントをクリア
	s.eventQueue = make([]module.Event, 0)
	s.LastSendTime = time.Now()

	return nil
}

// バッチサイズを超えたかどうかを確認
func (s *EventSender) IsOverBatchSize() bool {
	return len(s.eventQueue) >= s.BatchSize
}

// 最後の送信から一定時間経過したかどうかを確認
func (s *EventSender) IsOverTime() bool {
	return time.Since(s.LastSendTime) > 5*time.Second
}
