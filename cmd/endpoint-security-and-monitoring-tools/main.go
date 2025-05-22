package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mniyk/endpoint-security-and-monitoring-tools/internal/config"
	"github.com/mniyk/endpoint-security-and-monitoring-tools/internal/transmission"
	"github.com/mniyk/endpoint-security-and-monitoring-tools/internal/userinfo"
	"github.com/mniyk/endpoint-security-and-monitoring-tools/module"
	"github.com/mniyk/endpoint-security-and-monitoring-tools/module/usb"
)

func main() {
	// シグナルを受信するチャネルを作成
	sigChan := make(chan os.Signal, 1)

	// 終了シグナルを登録
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// アプリケーションの開始
	log.Println("[Main] Start security monitoring...")

	// JSONファイルから設定を読み込む
	cfg, err := config.LoadConfig("config.json")
	if err != nil {
		log.Fatalf("[Main] Failed load config.json: %v", err)
	}

	// ユーザー情報を取得
	userInfo := userinfo.NewUserInfo()

	// イベント送信機能を初期化
	eventDispatcher := transmission.NewEventSender(5)

	// モジュールの管理
	manager := module.NewManager(cfg)
	registerModules(manager, cfg, userInfo, eventDispatcher)

	// すべてのモジュールを初期化
	initErrors := manager.InitializeAllModules()
	if len(initErrors) > 0 {
		for name, err := range initErrors {
			log.Fatalf("[Main] Failed initialize module (%s): %v", name, err)
		}
	}

	// すべてのモジュールを開始
	startErrors := manager.StartAllModules()
	if len(startErrors) > 0 {
		for name, err := range startErrors {
			log.Fatalf("[Main] Failed start module (%s): %v", name, err)
		}
	}

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			if eventDispatcher.IsOverBatchSize() || eventDispatcher.IsOverTime() {
				// 保留中のイベントを送信
				eventDispatcher.Flush()
			}
		}
	}()

	// シグナルを待機（無限ループを削除）
	sig := <-sigChan
	log.Printf("[Main] Received termination signal: %v", sig)

	// クリーンアップ処理
	log.Println("[Main] Start cleanup...")

	// すべてのモジュールを停止
	stopErrors := manager.StopAllModules()
	if len(stopErrors) > 0 {
		for name, err := range stopErrors {
			log.Fatalf("[Main] Failed stop module (%s): %v", name, err)
		}
	}

	// 強制的にイベントキューをフラッシュ
	eventDispatcher.Flush()

	log.Println("[Main] Stop security monitoring...")
}

// モジュールを登録
func registerModules(manager *module.Manager, cfg *config.Configs, userInfo *userinfo.UserInfo, eventDispatcher transmission.EventDispatcher) {
	for name := range cfg.Modules {
		var moduleInstance module.Module

		switch name {
		case "usb_file_transfer_monitoring":
			config := usb.NewMonitorConfig(cfg.Modules[name])
			moduleInstance = usb.NewMonitor(config, userInfo, eventDispatcher)
		}

		if moduleInstance != nil {
			if err := manager.RegisterModule(name, moduleInstance); err != nil {
				log.Fatalf("[Main] Failed %s registration: %v", name, err)
			}
		}
	}
}
