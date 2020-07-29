package myEncode

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"io"
	"os"
)

/*
单向散列函数：获取消息的指纹
对输入的数据生成一个唯一的简短的摘要或是指纹

对于同一算法有如下特性：
1、输入内容不变时输出内容也不变
2、输入内容改变时，哪怕就一点点，输出内容千差万别
3、无论输入的内容长度大小如何，大或是小，生成的哈希长度相同
4、哈希运算是对输入内容做摘要（指纹），无法根据哈希值反推回原值
5、具有抗碰撞性

sha256：
64 * 4 = 256 bit
2^256 种可能

应用场景：
1、检测软件是否被篡改
2、消息认证码
3、数字签名：先对数据（较大）算哈希值，再用私钥对哈希值进行签名
4、伪随机数生成器
5、一次性口令
6、密码存储

*/

//MD5
/*
md5：生成 hash长度为 128 bit(16 byte)
*/
//方式一：对多量数据进行哈希运算
func GetMd5Info(info string) []byte {
	//1、创建一个哈希器
	hash := md5.New()

	io.WriteString(hash, info)

	//2、执行 Sum 操作，得到哈希值
	//如果参数不是nil，返回的值为 参数b+hash值
	hashInfo := hash.Sum(nil)

	return hashInfo
}

//方式二
func GetMd5Data(info []byte) []byte {
	hash := md5.Sum(info)

	//将数组转换为切片
	return hash[:]
}

//SHA1
func GetSha1Info(filePath string) ([]byte, error) {
	//1、open 文件
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	//2、创建基于sha1算法的Hash对象
	myHash := sha1.New()

	//3、将文件数据拷贝给哈希对象
	_, err = io.Copy(myHash, file)
	if err != nil {
		return nil, err
	}

	//4、hash sum 操作计算文件的哈希值
	hashValue := myHash.Sum(nil)

	return hashValue, nil
}

//SHA2
/*
包括：SHA-224, SHA-256, SHA-384, SHA=512
*/
//使用打开文件方式获取哈希
func GetSha256Info(filePath string) ([]byte, error) {
	//1、open 文件
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	//2、创建 hash
	hash := sha256.New()

	//3、copy 句柄
	_, err = io.Copy(hash, file)
	if err != nil {
		return nil, err
	}

	//4、hash sum 操作
	hashValue := hash.Sum(nil)

	return hashValue, nil
}
