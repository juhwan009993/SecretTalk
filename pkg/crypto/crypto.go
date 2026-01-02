package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
)

//키 쌍(비공개키, 공개키) 생성
func GenerateKeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	//P256 곡선으로 키 쌍 생성
	curve := ecdh.P256()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privKey, privKey.PublicKey(), nil
}

//공유 비밀키(Shared Secret) 유도
func DeriveSharedSecret(priv *ecdh.PrivateKey, peerPubBytes []byte) ([]byte, error) {
	curve := ecdh.P256()
	peerPub, err := curve.NewPublicKey(peerPubBytes)
	if err != nil {
		return nil, err
	}
	//ECDH 연산 수행
	secret, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

//메시지 암호화
func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	//Nonce 생성
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	//암호화 + 태그 생성
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

//메시지 복호화
func Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//AES-GCM 암호화 객체 생성
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	//Nonce 검증
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	//복호화 + 무결성 검증
	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
