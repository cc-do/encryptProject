package myRSA

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

/*
1、对密文进行 D次方处理（D:Decrypt）
2、对 N 进行取模
3、根据字符表转换为原来的明文

私钥：{D,N}，私钥由 D,N 组成
D如何获得，这是最难的
只有知道了是哪两个大素数，才能计算出 D

*/

//私钥解密

func RsaDecrypt(filePath string, cipherData []byte) ([]byte, error) {
	//1、通过私钥文件读取私钥信息 ==> pem encode的数据
	info, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	//2、通过 pem decode 得到block中的der编码数据
	block, _ := pem.Decode(info) //rest参数是未解码完的数据
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("私钥数据出错")
	}

	//3、解码得到私钥
	derText := block.Bytes
	privateKey, err := x509.ParsePKCS1PrivateKey(derText)
	if err != nil {
		return nil, err
	}

	//4、使用公钥加密
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherData)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}
