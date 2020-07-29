package test

import (
	"fmt"
	"io"
	"myDES"
	"os"
	"testing"
)

func TestDes(t *testing.T) {
	src := []byte("12345678")
	key := []byte("12345678")

	dst := myDES.DesCbcEncrypt(src, key)
	fmt.Printf("cipherData : %x\n", dst)

	plainText := myDES.DesCbcDecrypt(dst, key)
	fmt.Printf("plainText str : %s\n", plainText)
	fmt.Printf("plainText hex : %x\n", plainText)
}

func TestFile(t *testing.T) {
	/*
		file, err := os.Create("/data/private.pem")
			if err != nil {
				panic(err)
			}
			defer file.Close()
	*/

	file, err := os.Open("data/RSAPrivateKey.pem")
	if err != nil {
		panic(err)
	}

	defer file.Close()

	var buf [1024]byte
	var content []byte

	for {
		n, err := file.Read(buf[:])
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}
		content = append(content, buf[:n]...)
	}
	fmt.Println(string(content))
}

func TestBinary(t *testing.T) {

}
