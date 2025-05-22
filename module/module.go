package module

// 実装すべきメソッドを定義
type Module interface {
	Initialize() error  // モジュールの初期化
	Start() error       // モニタリングの開始
	Stop() error        // モニタリングの停止
	GetEvents() []Event // モジュールが検出したイベントを取得
}
