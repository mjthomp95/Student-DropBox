package email

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
        "bufio"
        "os"
        "crypto/sha256"
        "golang.org/x/crypto/ssh/terminal"
        "golang.org/x/crypto/pbkdf2"
)

func DecryptPassword(dir string) string {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	fmt.Print("Password: ")
        bytePassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))
        if err != nil {
                panic(err)
        }
	saltFile, err1 := os.Open(dir + "/email/salt")
        if err1 != nil {
                panic(err1)
        }
        defer saltFile.Close()
        scanner := bufio.NewScanner(saltFile)
        scanner.Scan()
        salt := []byte(scanner.Text())
	key := pbkdf2.Key(bytePassword, salt, 4096, 32, sha256.New)
	passwordFile, err2 := os.Open(dir + "/email/passwordEncrypt")
        if err2 != nil {
                panic(err2)
        }
        defer passwordFile.Close()
        scanner = bufio.NewScanner(passwordFile)
        scanner.Scan()
        ciphertext := []byte(scanner.Text())

	block, err3 := aes.NewCipher(key)
	if err3 != nil {
		panic(err3)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)
	return string(ciphertext)
}
