package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", "example.com:443", "接続先（host:port）")
	serverName := flag.String("servername", "", "証明書を検証する名前")
	timeout := flag.Duration("timeout", 5*time.Second, "TCPとTLSの合計制限時間")
	flag.Parse()

	if *timeout <= 0 {
		return fmt.Errorf("timeoutには正の時間を指定してください")
	}

	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		return fmt.Errorf("接続先の形式が不正です: %w", err)
	}

	name := *serverName
	if name == "" {
		name = host
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// ① TCP接続する
	dialer := &net.Dialer{}

	rawConn, err := dialer.DialContext(ctx, "tcp", *addr)
	if err != nil {
		return fmt.Errorf("TCP接続失敗（名前解決を含む）: %w", err)
	}
	defer rawConn.Close()

	fmt.Println("TCP接続成功:", rawConn.RemoteAddr())

	// ② 既存のTCP接続からTLSクライアントを作る
	conn := tls.Client(rawConn, &tls.Config{
		ServerName: name,
	})

	// ③ TLSハンドシェイクする
	if err := conn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLSハンドシェイク失敗: %w", err)
	}
	defer conn.Close()

	fmt.Println("TLSハンドシェイク成功")

	state := conn.ConnectionState()

	fmt.Println("TLSバージョン:", tls.VersionName(state.Version))
	fmt.Println("暗号スイート:", tls.CipherSuiteName(state.CipherSuite))

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]

		fmt.Println("証明書の対象ドメイン:", cert.DNSNames)
		fmt.Println("証明書の発行者:", cert.Issuer.String())
		fmt.Println("有効期間の開始:", cert.NotBefore.Format(time.RFC3339))
		fmt.Println("有効期間の終了:", cert.NotAfter.Format(time.RFC3339))
	}

	fmt.Println("検証済み証明書チェーン数:", len(state.VerifiedChains))

	return nil
}