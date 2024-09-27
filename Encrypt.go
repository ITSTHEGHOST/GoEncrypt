package main

import (
        "crypto/aes"
        "crypto/cipher"
        "crypto/rand"
        "fmt"
        "io/ioutil"
        "os"
)

func main() {
        if len(os.Args) != 3 {
                fmt.Println("Usage: go run encrypt.go <filename> <key>")
                return
        }

        filename := os.Args[1]
        key := []byte(os.Args[2])

        // Ensure the key length is valid
        if len(key) != 16 && len(key) != 24 && len(key) != 32 {
                fmt.Println("Key length must be 16, 24, or 32 bytes!")
                return
        }

        // Read the file content
        plaintext, err := ioutil.ReadFile(filename)
        if err != nil {
                fmt.Println("Error reading file:", err)
                return
        }

        // Encrypt the content
        ciphertext, err := encrypt(plaintext, key)
        if err != nil {
                fmt.Println("Error encrypting:", err)
                return
        }

        // Write encrypted content to a new file
        err = ioutil.WriteFile(filename+".enc", ciphertext, 0644)
        if err != nil {
                fmt.Println("Error writing encrypted file:", err)
                return
        }

        fmt.Println("File encrypted successfully:", filename+".enc")
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
        block, err := aes.NewCipher(key)
        if err != nil {
                return nil, err
        }

        // Pad plaintext
        padding := block.BlockSize() - len(plaintext)%block.BlockSize()
        padtext := append(plaintext, byte(padding))
        for i := 1; i < padding; i++ {
                padtext = append(padtext, byte(padding))
        }

        // Create IV
        ciphertext := make([]byte, aes.BlockSize+len(padtext))
        iv := ciphertext[:aes.BlockSize]
        if _, err := rand.Read(iv); err != nil {
                return nil, err
        }

        // Encrypt the data
        mode := cipher.NewCBCEncrypter(block, iv)
        mode.CryptBlocks(ciphertext[aes.BlockSize:], padtext)

        return ciphertext, nil
}
