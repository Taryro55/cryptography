package main

var (
	message string
	passphrase = []byte("1234567812345678")

)

type (
	Ciphers interface {
		encryptAES() []byte
		decryptAES() []byte
	}
	
	
	Enigma struct {
		decrypted []byte
		encrypted []byte
	}

	// Password struct {
	// 	decrypted string
	// 	encrypted string
	// }
)