package main

import (
	"fmt"
)

func main() {
	AES_Example()
	sha256_Example()
}

func AES_Example() {
	fmt.Print(">> ")
	fmt.Scanln(&message)

	fmt.Println("\n\n This is the AES cipher of text. \n\n")
	enigma := Enigma{[]byte(message), nil}

	cipherStr, err := enigma.encryptAES(passphrase)
	if err != nil {
		panic(err)
	}
	fmt.Println("\t", cipherStr)

	_, err = enigma.decryptAES(passphrase)
	if err != nil {
		panic(err)
	}
	fmt.Println("\t", string(enigma.decrypted))
}

func sha256_Example() {
	fmt.Println("\n\n This is the hashing of text. \n\n")
	name := Enigma{decrypted: []byte(message), encrypted: nil}
	name.encryptSHA256()
	fmt.Println("\t", name.encryptSHA256().stringByte())
}