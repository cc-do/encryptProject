package myRSA

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

/*
需求：生成并保存私钥，公钥

生成私钥：
1、GenerateKey函数使用随机数生成器random生成一对具有指定字位数的RSA密钥
func GenerateKey(random io.Reader, bits int) (*PrivateKey, error)
	--参数1：随机数，crypto/rand 随机数生成器
	--参数2：密钥长度
	--返回值：私钥

2、要对生成的私钥进行编码处理，x509：按照规则进行序列化处理，生成der编码的数据
func MarshalPKCS1PrivateKey(key *rsa.PrivateKey) []byte

3、创建 Block，代表PEM编码的结构，并填入der编码的数据
type Block struct {
	Type    string            // 来自前言的类型（"RSA PRIVATE KEY"）
	Headers map[string]string // 可选的头项
	Bytes   []byte            // 内容解码后的数据，一般是der编码的ASN.1结构
}

4、将 PEM Block数据写入到磁盘文件中
func Encode(out io.Writer, b *Block) error

*/

//生成私钥文件
//使用随机数按照一定的规则生成的
func GenRsaKey(bits int) error {
	fmt.Println("+++++++++++++++生成私钥+++++++++++++++")
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	keyStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyStream,
	}

	filePrivate, err := os.Create("RSAPrivateKey.pem")
	if err != nil {
		return err
	}
	defer filePrivate.Close()

	err = pem.Encode(filePrivate, &block)
	if err != nil {
		return err
	}

	fmt.Println("+++++++++++++++生成公钥+++++++++++++++")
	/*
		公钥必须要通过私钥推出，这样公钥和私钥才能匹配起来

		1、通过私钥来获取公钥
		2、对生成的公钥进行编码处理，x509.MarshalPKIXPublicKey 将其序列化生成der编码的数据
		3、创建 pem编码结构的 Block，填入der编码的数据
		4、将block数据写入磁盘中
	*/

	publicKey := privateKey.PublicKey //注意是对象不是地址
	derPkey := x509.MarshalPKCS1PublicKey(&publicKey)

	block = pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkey,
	}

	filePublic, err := os.Create("RSAPublicKey.pem")
	if err != nil {
		return err
	}
	defer filePublic.Close()

	err = pem.Encode(filePublic, &block)
	if err != nil {
		return err
	}

	return nil
}
