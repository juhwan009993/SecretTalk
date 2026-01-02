package main

import (
	"fmt"
	"net"
	"sync"
)

//클라이언트 목록
var (
	clients   = make(map[net.Conn]bool)
	clientsMu sync.Mutex
)

//서버 실행
func main() {
	//서버 리스너 생성
	listener, err := net.Listen("tcp", ":9000")
	if err != nil {
		panic(fmt.Sprintf("[Error] Failed to listen: %v", err))
	}
	fmt.Println("[System] Server is listening on :9000...")

	//클라이언트 연결 대기
	for {
		//클라이언트 연결 수락
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("[Error] Failed to accept connection: %v\n", err)
			continue
		}

		//클라이언트 목록 업데이트
		clientsMu.Lock()
		clients[conn] = true
		clientsMu.Unlock()

		//클라이언트 연결 알림
		fmt.Printf("[System] New client connected: %s\n", conn.RemoteAddr())

		go handleConnection(conn)
	}
}
//클라이언트 연결
func handleConnection(conn net.Conn) {
	defer conn.Close()
	//클라이언트 연결 종료 시 클라이언트 목록 업데이트
	defer func() {
		clientsMu.Lock()
		delete(clients, conn)
		clientsMu.Unlock()
		fmt.Printf("[System] Client disconnected: %s\n", conn.RemoteAddr())
	}()

	buf := make([]byte, 4096)
	//메시지 수신
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		broadcast(buf[:n], conn)
	}
}

//메시지 브로드캐스트
func broadcast(data []byte, sender net.Conn) {
	clientsMu.Lock()
	defer clientsMu.Unlock()

	for client := range clients {
		if client != sender { //중복 전송 방지
			client.Write(data)
		}
	}
}
