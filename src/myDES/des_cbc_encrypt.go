package myDES

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"log"
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

//输入明文，密钥，并输出密文
func DesCbcEncrypt(src, key []byte) []byte {
	fmt.Printf("加密开始，输入的数据为：%s\n", src)
	//1. 创建并返回一个使用 DES算法的 cipher.Block接口
	block, err := des.NewCipher(key)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("block size : ", block.BlockSize())

	//2. 对最后一个明文分组进行数据填充
	src = PaddingInfo(src, block.BlockSize())

	//3. 引入CBC模式
	iv := bytes.Repeat([]byte("1"), block.BlockSize())
	bm := cipher.NewCBCEncrypter(block, iv)

	//4、加密操作
	bm.CryptBlocks(src /*加密后的密文*/, src /*明文*/)

	fmt.Printf("加密结束，输出的数据为：%x\n", src)
	return src
}

//填充函数，输入明文，分组长度，输出：填充后的数据
func PaddingInfo(src []byte, blockSize int) []byte {
	//1、得到明文长度
	length := len(src)

	//2、需要填充的数量
	remains := length % blockSize
	paddingNumber := blockSize - remains

	//3、把填充的数值转换为字符
	s1 := byte(paddingNumber)

	//4、把字符拼成数组
	s2 := bytes.Repeat([]byte{s1}, paddingNumber)

	//5、把拼成的数组追加到src后面
	src = append(src, s2...)

	return src
}
