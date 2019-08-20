package email

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"bufio"
	"os"
	"crypto/sha256"	
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/crypto/pbkdf2"	
)

func encryptPassword(dir string) {
	fmt.Print("Password: ")
	bytePassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}
	salt := make([]byte, 8)
	if _, err := rand.Reader.Read(salt); err != nil {
		panic(err)
	}
	f, er := os.OpenFile(dir + "/email/salt", os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)
	if er != nil {
		panic(er)
	}
	defer f.Close()
	_, err = f.Write(salt)
	if err != nil {
		panic(err)
	}
	key := pbkdf2.Key(bytePassword, salt, 4096, 32, sha256.New)
	passwordFile, err1 := os.Open(dir + "/email/password")
	if err1 != nil {
		panic(err1)
	}
	defer passwordFile.Close()
	scanner := bufio.NewScanner(passwordFile)
	scanner.Scan()
	plaintext := []byte(scanner.Text())
	
	block, err2 := aes.NewCipher(key)
	if err2 != nil {
		panic(err2)
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	file, err3 := os.Create(dir + "/email/passwordEncrypt")
	if err3 != nil {
		panic(err3)
	}
	file.Write(ciphertext)
	file.Close()
}

