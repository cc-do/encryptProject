package myAES

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
	"utils"
)

//输入密文，密钥，初始向量，并输出明文
func AesCbcDecrypt(cipherData, key, iv []byte) []byte {
	fmt.Printf("解密开始，输入的数据为：%x\n", cipherData)
	//1. 创建并返回一个使用 DES算法的 cipher.Block接口
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("block size : ", block.BlockSize())

	//2. 引入CBC模式
	//iv := bytes.Repeat([]byte("1"), block.BlockSize())
	bm := cipher.NewCBCDecrypter(block, iv)

	//3、解密操作
	bm.CryptBlocks(cipherData /*解密后的明文*/, cipherData /*密文*/)

	//4. 对最后一个明文分组去除填充
	plainText := utils.DelPaddingInfo(cipherData)

	fmt.Printf("解密结束，输出的数据为：%s\n", plainText)
	return plainText
}
