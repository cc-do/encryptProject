package myDES

import (
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"log"
	"utils"
)

/*
需求：
算法：des；分组模式：CBC

DES:
密钥：8 bytes
分组长度：8 bytes

CBC:
1、提供初始化向量，长度与分组长度相同，为 8 bytes
2、需要填充

加密分析：
1. 创建并返回一个使用 DES算法的 cipher.Block接口
密钥长度为64bit, 即 64/8 = 8字节(byte)
func NewCipher(key []byte) (cipher.Block, error)
	--包名：des
	--参数：密钥，8 bytes
	--返回值：一个 cipher.Block接口
	type Block interface {
	// 返回加密字节块的大小
	BlockSize() int

	// 加密src的第一块数据并写入dst，src和dst可指向同一内存地址
	Encrypt(dst, src []byte)

	// 解密src的第一块数据并写入dst，src和dst可指向同一内存地址
	Decrypt(dst, src []byte)
}

2. 对最后一个明文分组进行数据填充
DES是以 64 比特的明文（比特序列）为一个单位来进行加密的
最后一组不够64bit, 则需要进行数据填充

3. 引入CBC模式，创建一个密码分组为链接模式的, 底层使用 DES加密的 BlockMode接口，初始向量 iv 的长度等于分组长度
func NewCBCEncrypter(b Block, iv []byte) BlockMode
	--包名：cipher
	--参数：1、cipher.Block
	--参数：2、iv 初始化向量
	--返回值：BlockMode，分组模式，里面提供加解密方法
	type BlockMode interface {
	// 返回加密字节块的大小
	BlockSize() int
	// 加密或解密连续的数据块，src的尺寸必须是块大小的整数倍，src和dst可指向同一内存地址
	CryptBlocks(dst, src []byte)
}
4. 加密连续的数据块


解密分析：
1. 创建并返回一个使用 DES算法的 cipher.Block接口
密钥长度为64bit, 即 64/8 = 8字节(byte)
func NewCipher(key []byte) (cipher.Block, error)
	--包名：des
	--参数：密钥，8 bytes
	--返回值：一个 cipher.Block接口
	type Block interface {
	// 返回加密字节块的大小
	BlockSize() int

	// 加密src的第一块数据并写入dst，src和dst可指向同一内存地址
	Encrypt(dst, src []byte)

	// 解密src的第一块数据并写入dst，src和dst可指向同一内存地址
	Decrypt(dst, src []byte)
}

2. 引入CBC模式，创建一个密码分组为链接模式的, 底层使用 DES加密的 BlockMode接口，初始向量 iv 的长度等于分组长度
func NewCBCDecrypter(b Block, iv []byte) BlockMode
	--包名：cipher
	--参数：1、cipher.Block
	--参数：2、iv 初始化向量
	--返回值：BlockMode，分组模式，里面提供加解密方法
	type BlockMode interface {
	// 返回加密字节块的大小
	BlockSize() int
	// 加密或解密连续的数据块，src的尺寸必须是块大小的整数倍，src和dst可指向同一内存地址
	CryptBlocks(dst, src []byte)
}

3、解密操作

4、去除填充

*/

//输入密文，密钥，并输出明文
func DesCbcDecrypt(cipherData, key, iv []byte) []byte {
	fmt.Printf("解密开始，输入的数据为：%x\n", cipherData)
	//1. 创建并返回一个使用 DES算法的 cipher.Block接口
	block, err := des.NewCipher(key)
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
