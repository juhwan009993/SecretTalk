package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"secrettalk/pkg/crypto" 
)

// 프로토콜 타입
const (
	TypePubKey = 0x01
	TypeMsg    = 0x02
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("--------------------------------")
	fmt.Println("         SecretTalk Client       ")
	fmt.Println("--------------------------------")
	fmt.Print("[System] Enter your nickname: ")

	scanner.Scan()
	nickname := strings.TrimSpace(scanner.Text())
	if nickname == "" {
		nickname = "Anonymous"
	}
	fmt.Printf("[System] Hello, '%s'!\n", nickname)
	//키 생성
	privKey, pubKey, err := crypto.GenerateKeyPair()
	if err != nil {
		panic(fmt.Sprintf("[Error] Failed to generate keys: %v", err))
	}

	//서버 접속
	conn, err := net.Dial("tcp", "localhost:9000")
	if err != nil {
		panic(fmt.Sprintf("[Error] Failed to connect: %v", err))
	}
	defer conn.Close()

	// 동기화 변수
	var sharedSecret []byte
	handshakeDone := make(chan bool)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				fmt.Println("[Error] Disconnected from server.")
				os.Exit(0)
			}

			msgType := buf[0]
			data := buf[1:n]

			if msgType == TypePubKey {
				//키 교환 패킷
				if sharedSecret == nil {
					sharedSecret, err = crypto.DeriveSharedSecret(privKey, data)
					if err != nil {
						fmt.Printf("[Error] Key Exchange Failed: %v\n", err)
						continue
					}
					handshakeDone <- true
				}

			} else if msgType == TypeMsg {
				//메시지 패킷
				if sharedSecret == nil { continue }

				// 복호화
				plaintext, err := crypto.Decrypt(sharedSecret, data)
				if err != nil {
					fmt.Printf("[Error] Decryption failed: %v\n> ", err)
					continue
				}
				
				//프롬프트 덮어쓰기 방지
				fmt.Printf("\r%s\n> ", string(plaintext))
			}
		}
	}()

	//명령어 대기 (/connect)
	fmt.Println("[System] Type '/connect' to start secure chat.")

	for {
		fmt.Print("Command> ")
		if !scanner.Scan() { return }
		input := strings.TrimSpace(scanner.Text())
		//키 교환 시작
		if input == "/connect" {
			conn.Write(append([]byte{TypePubKey}, pubKey.Bytes()...))
			fmt.Println("[System] Key sent. Waiting for peer response...")
			break
		} else {
			fmt.Println("[System] Invalid command. Use /connect")
		}
	}

	<-handshakeDone 
	//키 교환 완료
	fmt.Println("\n[System] Secure Channel Established!")
	fmt.Print("> ")
	//메시지 주고받기
	for scanner.Scan() {
		msg := scanner.Text()
		if strings.TrimSpace(msg) == "" {
			fmt.Print("> ")
			continue
		}
		//메시지 형태로 조합
		//닉네임: 메시지 형태로 조합
		formattedMsg := fmt.Sprintf("[%s] %s", nickname, msg)

		//암호화
		encryptedMsg, err := crypto.Encrypt(sharedSecret, []byte(formattedMsg))
		if err != nil {
			fmt.Printf("[Error] Encryption failed: %v\n> ", err)
			continue
		}

		conn.Write(append([]byte{TypeMsg}, encryptedMsg...))
		fmt.Print("> ")
	}
}