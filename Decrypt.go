package main

import (
        "crypto/aes"
        "crypto/cipher"
        "fmt"
        "io/ioutil"
        "os"
)

func main() {
        if len(os.Args) != 3 {
                fmt.Println("Usage: go run decrypt.go <encrypted_filename> <key>")
                return
        }

        encryptedFilename := os.Args[1]
        key := []byte(os.Args[2])

        // Ensure the key length is valid
        if len(key) != 16 && len(key) != 24 && len(key) != 32 {
                fmt.Println("Key length must be 16, 24, or 32 bytes!")
                return
        }

        // Read the encrypted file content
        ciphertext, err := ioutil.ReadFile(encryptedFilename)
        if err != nil {
                fmt.Println("Error reading file:", err)
                return
        }

        // Decrypt the content
        plaintext, err := decrypt(ciphertext, key)
        if err != nil {
                fmt.Println("Error decrypting:", err)
                return
        }

        // Write decrypted content to a new file
        err = ioutil.WriteFile(encryptedFilename+".dec", plaintext, 0644)
        if err != nil {
                fmt.Println("Error writing decrypted file:", err)
                return
        }

        fmt.Println("File decrypted successfully:", encryptedFilename+".dec")
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
        block, err := aes.NewCipher(key)
        if err != nil {
                return nil, err
        }

        if len(ciphertext) < aes.BlockSize {
                return nil, fmt.Errorf("ciphertext too short")
        }

        // Extract IV from the ciphertext
        iv := ciphertext[:aes.BlockSize]
        ciphertext = ciphertext[aes.BlockSize:]

        // Decrypt the data
        mode := cipher.NewCBCDecrypter(block, iv)
        mode.CryptBlocks(ciphertext, ciphertext)

        // Unpad the plaintext
        padding := ciphertext[len(ciphertext)-1]
        if int(padding) > aes.BlockSize {
                return nil, fmt.Errorf("padding size is invalid")
        }
        return ciphertext[:len(ciphertext)-int(padding)], nil
}
