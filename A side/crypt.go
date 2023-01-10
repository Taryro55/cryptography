package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// * encryptSHA256 is a method of the Enigma struct that encrypts the Enigma struct's decrypted field using the SHA-256 hash function.
func (u *Enigma) encryptSHA256() *Enigma {
	x := sha256.Sum256(u.decrypted) // Calculate the SHA-256 hash of the decrypted data
	u.encrypted = x[:]              // Convert from [32]byte to []byte and store the hash
	return u
}

// * stringByte is a method of the Enigma struct that returns the Enigma struct's encrypted field as a hexadecimal string.
func (u Enigma) stringByte() string {
	return fmt.Sprintf("%x\n\n", string(u.encrypted[:])) // Convert the encrypted data to a hexadecimal string
}

// * encryptAES is a method of the Enigma struct that takes a key as input and returns the encrypted version of the Enigma struct's decrypted field as output.
func (e *Enigma) encryptAES(key []byte) (cipherStr string, err error) {
	decrypted := e.decrypted
	byteText := make([]byte, aes.BlockSize+len(decrypted)) // Create a new slice to store the encrypted data

	initVector := byteText[:aes.BlockSize] // Generate a random initialization vector (IV)
	if _, err := io.ReadFull(rand.Reader, initVector); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key) // Create a new AES cipher using the key
	if err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, initVector)              // Create a new Cipher Feedback (CFB) stream encrypter
	stream.XORKeyStream(byteText[aes.BlockSize:], []byte(decrypted)) // Encrypt the decrypted data and store it in the byteText slice

	cipherString := fmt.Sprintf("%x\n", byteText[aes.BlockSize:]) // Convert the encrypted data to a hexadecimal string (readable stuff)

	e.encrypted = byteText
	return cipherString, nil
}

// * decryptAES is a method of the Enigma struct that takes a key as input and returns the decrypted version of the Enigma struct encrypted field as output.
func (e *Enigma) decryptAES(key []byte) (plainText string, err error) {
	byteText := e.encrypted

	initVector := byteText[:aes.BlockSize] // Extract the initialization vector (initVector) from the encrypted data
	block, err := aes.NewCipher(key) // Create a new AES cipher using the key
	if err != nil {
		return "", err
	}

	stream := cipher.NewCFBDecrypter(block, initVector) // Create a new CFB (Cipher Feedback) stream decrypter
	stream.XORKeyStream(byteText[aes.BlockSize:], byteText[aes.BlockSize:]) // Decrypt the encrypted data and store it in the byteText slice

	decipherString := fmt.Sprintf("%s\n", byteText[aes.BlockSize:]) // Convert the decrypted data to a string

	e.decrypted = []byte(decipherString)
	return decipherString, nil
}

// func (p *Password) encryptAES(key string) (plainText string, err error) {
//     decrypted := []byte(p.decrypted)
// 	byteText := make([]byte, aes.BlockSize+len(decrypted)) // Create a new slice to store the encrypted data

// 	initVector := byteText[:aes.BlockSize] // Generate a random initialization vector (IV)
// 	if _, err := io.ReadFull(rand.Reader, initVector); err != nil {
// 		return "", err
// 	}
// 	block, err := aes.NewCipher([]byte(key)) // Create a new AES cipher using the key
// 	if err != nil {
// 		return "", err
// 	}

// 	stream := cipher.NewCFBEncrypter(block, initVector)              // Create a new Cipher Feedback (CFB) stream encrypter
// 	stream.XORKeyStream(byteText[aes.BlockSize:], []byte(decrypted)) // Encrypt the decrypted data and store it in the byteText slice

// 	cipherString := fmt.Sprintf("%x\n", byteText[aes.BlockSize:]) // Convert the encrypted data to a hexadecimal string (readable stuff)

// 	p.encrypted = cipherString
// 	return cipherString, nil
// }

// func (p *Password) decryptAES(key string) (plainText string, err error) {
//     byteText := []byte(p.encrypted)

// 	initVector := byteText[:aes.BlockSize] // Extract the initialization vector (initVector) from the encrypted data
// 	block, err := aes.NewCipher([]byte(key)) // Create a new AES cipher using the key
// 	if err != nil {
// 		return "", err
// 	}

// 	stream := cipher.NewCFBDecrypter(block, initVector) // Create a new CFB (Cipher Feedback) stream decrypter
// 	stream.XORKeyStream(byteText[aes.BlockSize:], byteText[aes.BlockSize:]) // Decrypt the encrypted data and store it in the byteText slice

// 	decipherString := fmt.Sprintf("%s\n", byteText[aes.BlockSize:]) // Convert the decrypted data to a string

// 	p.decrypted = decipherString
// 	return decipherString, nil
// }