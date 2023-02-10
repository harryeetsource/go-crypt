package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
)

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := cipher.NewCFBEncrypter(block, iv).XORKeyStream(ciphertext[aes.BlockSize:], plaintext); err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext is too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	plaintext := make([]byte, len(ciphertext))
	if _, err := cipher.NewCFBDecrypter(block, iv).XORKeyStream(plaintext, ciphertext); err != nil {
		return nil, err
	}

	return plaintext, nil
}

func main() {
	// Read the binary file into memory
	plaintext, err := ioutil.ReadFile("binary.bin")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Generate a random encryption key
	key := make([]byte, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
	fmt.Println(err)
	os.Exit(1)
}
	cipher.NewCFBEncrypter(block, make([]byte, aes.BlockSize)).XORKeyStream(key, key)

	}

	// Encrypt the binary
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	

	// Build the unpacking stub
stub := []byte(`
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io/ioutil"
	"os"
)

var key = []byte{}

func decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext is too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	plaintext := make([]byte, len(ciphertext))
	if _, err := cipher.NewCFBDecrypter(block, iv).XORKeyStream(plaintext, ciphertext); err != nil {
		return nil, err
	}

	return plaintext, nil
}

func main() {
	// Read the encrypted binary into memory
	ciphertext, err := ioutil.ReadFile("encrypted.bin")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Decrypt the binary
	plaintext, err := decrypt(ciphertext)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Write the decrypted binary to a new file
	if err := ioutil.WriteFile("decrypted.bin", plaintext, 0644); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
`)


	// Add the key to the stub and write the packed binary to a new file
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, key)
	packed := append(stub, buf.Bytes()...)
	if err := ioutil.WriteFile("packed.bin", packed, 0644); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

