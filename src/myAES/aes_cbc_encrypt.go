package myAES

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
	"utils"
)

//输入明文，密钥，初始向量，并输出密文
func AesCbcEncrypt(src, key, iv []byte) []byte {
	fmt.Printf("加密开始，输入的数据为：%s\n", src)
	//1. 创建并返回一个使用 DES算法的 cipher.Block接口
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("block size : ", block.BlockSize())

	//2. 对最后一个明文分组进行数据填充
	src = utils.PaddingInfo(src, block.BlockSize())

	//3. 引入CBC模式
	//iv := bytes.Repeat([]byte("1"), block.BlockSize())
	bm := cipher.NewCBCEncrypter(block, iv)

	//4、加密操作
	bm.CryptBlocks(src /*加密后的密文*/, src /*明文*/)

	fmt.Printf("加密结束，输出的数据为：%x\n", src)
	return src
}
