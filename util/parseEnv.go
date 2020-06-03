package utils

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
	"strings"
)

func ParseEnvironment() {
	//useGlobalEnv := true
	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		log.Printf("Environment Variable file (.env) is not present.  Relying on Global Environment Variables")
		//useGlobalEnv = false
	}

	setEnvVariable("CLIENT_ID", os.Getenv("CLIENT_ID"))
	setEnvVariable("CLIENT_SECRET", os.Getenv("CLIENT_SECRET"))
	setEnvVariable("ISSUER", os.Getenv("ISSUER"))
	setEnvVariable("REDIRECT_URI", os.Getenv("REDIRECT_URI"))

	if os.Getenv("CLIENT_ID") == "" {
		log.Printf("Could not resolve a CLIENT_ID environment variable.")
		os.Exit(1)
	}

	if os.Getenv("CLIENT_SECRET") == "" {
		log.Printf("Could not resolve a CLIENT_SECRET environment variable.")
		os.Exit(1)
	}

	if os.Getenv("ISSUER") == "" {
		log.Printf("Could not resolve a ISSUER environment variable.")
		os.Exit(1)
	}

	if os.Getenv("REDIRECT_URI") == "" {
		log.Printf("Could not resolve a REDIRECT_URI environment variable.")
		os.Exit(1)
	}
}

func setEnvVariable(env string, current string) {
	if current != "" {
		return
	}

	file, _ := os.Open(".env")
	defer file.Close()

	lookInFile := bufio.NewScanner(file)
	lookInFile.Split(bufio.ScanLines)

	for lookInFile.Scan() {
		parts := strings.Split(lookInFile.Text(), "=")
		key, value := parts[0], parts[1]
		if key == env {
			os.Setenv(key, value)
		}
	}
}

func GenerateNonce() (string, error) {
	nonceBytes, err := GenerateRandomBytes(32)
	if err != nil {
		return "", fmt.Errorf("could not generate nonce")
	}

	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}

func IsPasswordMatch(hashedPwd string, plainPwd string) bool {
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, []byte(plainPwd))
	if err != nil {
		return false
	}

	return true
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func EncodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func DecodeBase64(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}
