package userinfo

import (
	"os"
)

// ユーザー情報の構造体
type UserInfo struct {
	UserName string
	HostName string
}

// 新しいUserInfoを作成
func NewUserInfo() *UserInfo {
	// ユーザー名を取得
	userName := os.Getenv("USERNAME")
	if userName == "" {
		userName = "unknown"
	}

	// ホスト名を取得
	hostName, err := os.Hostname()
	if err != nil {
		hostName = "unknown"
	}

	return &UserInfo{
		UserName: userName,
		HostName: hostName,
	}
}
