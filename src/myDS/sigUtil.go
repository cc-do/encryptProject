package myDS

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

/*
数字签名：消息是谁写的
公钥 ==> 加密
私钥 ==> 数字签名

签名过程：
1、将待发送数据进行 HASH 运算（sha256）得到 hash 值(256bit)
2、对 hash值使用私钥进行签名
3、将数据和签名一起发送给对方

验证过程：
1、将接收到的数据进行 HASH 运算得到 hash值
2、使用与私钥配套的公钥，对接收到的数字签名进行解密，得到被私钥签名的 hash值
3、对比两个 hash值是否一致

解决的问题：
1、不需要配送密钥，使用公钥进行解密
2、只要有公钥就能进行第三方证明
3、可以防止否认，私钥只有发送方才有，无法进行抵赖

注：
签名的数据不是数据本身，而是 hash值

*/

/*
私钥签名：
1、获取私钥，解析出私钥的内容
2、使用私钥进行数字签名

公钥认证：
1、提供公钥文件，解析出公钥内容
2、使用公钥进行数字签名的认证

*/

//私钥签名：提供私钥，签名数据，得到数字签名
func RsaSignData(filePath string, src []byte) ([]byte, error) {
	//1、获取私钥，解析出私钥的内容
	//通过私钥文件读取私钥信息 ==> pem encode的数据
	info, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	//通过 pem decode 得到block中的der编码数据
	block, _ := pem.Decode(info) //rest参数是未解码完的数据
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("私钥数据出错")
	}

	//解码得到私钥
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	//2、使用私钥进行数字签名
	//获取数据的哈希值
	hashValue := sha256.Sum256(src) //返回值为长度32的数组

	//执行签名操作
	signData, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashValue[:])
	if err != nil {
		return nil, err
	}

	return signData, nil
}

//公钥认证
func VerifySign(filePath string, sigData []byte, src []byte) error {
	//一、解析公钥内容
	//1、通过公钥文件读取公钥信息 ==> pem encode的数据
	info, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	//2、通过 pem decode 得到block中的der编码数据
	block, _ := pem.Decode(info) //rest参数是未解码完的数据
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("公钥数据出错")
	}

	//3、解码得到公钥
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return err
	}

	//二、使用公钥进行数字签名认证
	//获取接收到数据的 hash值
	hashValue := sha256.Sum256(src)

	//执行认证操作
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashValue[:], sigData)

	return err
}
