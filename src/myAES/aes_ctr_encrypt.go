package myAES

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
)

/*
需求：使用 AES，分组模式：CTR

AES：
	分组长度：16 byte
	密钥：16 byte

CTR：
	不需要填充
	需要提供一个数字

使用 AES 包
1. 创建并返回一个使用 AES算法的 cipher.Block接口，密钥长度为 128bit, 即 128/8 = 16字节(byte)
参数 key 为密钥，长度只能是16、24、32字节，用以选择AES-128、AES-192、AES-256
func NewCipher(key []byte) (cipher.Block, error)
	包：AES
	密钥
	cipher.Block接口

2. 选择分组模式 CTR
返回一个计数器模式的、底层采用 block生成 key流的 Stream接口，初始向量 iv的长度必须等于 block的块尺寸。
func NewCTR(block Block, iv []byte) Stream
	Block
	iv

3. 加密操作
type Stream interface {
    // 从加密器的 key流和 src中依次取出字节二者 xor后写入 dst，src和 dst可指向同一内存地址
    XORKeyStream(dst, src []byte)
}
*/

func AesCTREncrypt(src, key []byte) []byte {
	//1. 创建并返回一个使用 AES算法的 cipher.Block接口
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("AES block size : ", block.BlockSize())

	//2. 选择分组模式 CTR
	iv := bytes.Repeat([]byte("1"), block.BlockSize())
	stream := cipher.NewCTR(block, iv)

	//3. 加密操作
	stream.XORKeyStream(src /*密文*/, src /*明文*/)

	return src
}
