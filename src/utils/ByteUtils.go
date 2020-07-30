package utils

import "bytes"

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

//去除填充函数，输入明文，分组长度，输出：填充后的数据
func DelPaddingInfo(plainText []byte) []byte {
	//1、得到明文长度
	length := len(plainText)

	if length == 0 {
		return []byte{}
	}

	//2、获取最后一个字符
	lastByte := plainText[length-1]

	//3、把字符转换为数字
	paddingNumber := int(lastByte)

	//4、切片获取需要的数据
	return plainText[:length-paddingNumber]
}
