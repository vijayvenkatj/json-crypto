### **`json-crypto` - Secure JSON Encryption Library for Go**  

An enhanced version of the [`@harshiyer/json-crypto`](https://www.npmjs.com/package/@harshiyer/json-crypto) NPM package, rewritten in Go. This package provides AES encryption and decryption for JSON data, ensuring secure storage and transmission.

---

## **🚀 Features**  

- 🔒 AES-GCM encryption for JSON objects  
- 🛡️ PBKDF2-derived keys for better security  
- 📦 Base64 encoding for easy storage and transmission  
- 🔄 Seamless JSON serialization and deserialization  

---

## **📌 Installation**  

```sh
go get github.com/vijayvenkatj/json-crypto
```

---

## **🛠 Usage**  

### **Encrypt JSON**  

```go
package main

import (
	"fmt"
	"log"
	cryptohelper "github.com/vijayvenkatj/json-crypto"
)

func main() {
	key := []byte("01234567890123456789012345678901") // 32-byte key
	salt := []byte("randomsalt") // Salt for key derivation

	inputJSON := map[string]interface{}{
		"Passwords": []string{"password1", "password2"},
	}

	_, _, encryptedData, _, err := cryptohelper.ConvertToAES(inputJSON, key, salt)
	if err != nil {
		log.Fatal("Encryption failed:", err)
	}

	fmt.Println("Encrypted JSON:", encryptedData)
}
```

---

### **Decrypt JSON**  

```go
	decryptedJSON, err := cryptohelper.ConvertFromAES(encryptedData, key, salt)
	if err != nil {
		log.Fatal("Decryption failed:", err)
	}

	fmt.Println("Decrypted JSON:", decryptedJSON)
```

---

## **📜 License**  

MIT License © 2025 [Vijay J](https://github.com/vijayvenkatj)  
