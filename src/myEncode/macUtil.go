package myEncode

import (
	"crypto/hmac"
	"crypto/sha256"
)

/*
A ==> B
消息认证码：
假如A发送的消息是不可读的（一堆乱码），经过加密解密后发到B，此时还是不可读的
那么，B怎么判断这个消息就是A发的呢，无法判断是否经过篡改

解决方法：引入消息认证码
1、保证消息没有被篡改——消息的完整性
2、保证消息来自正确的发送者

消息认证码是一种与密钥相关的单向散列函数
使用步骤：
1、双方事先协商好密钥，并共享密钥
2、使用共享密钥对发送数据计算 MAC值
3、A将消息和 MAC值两者都发送给B
4、B根据接收到的消息使用共享密钥计算 MAC 值
5、B将计算的MAC值与从A处接收到的MAC值进行对比
6、一致则认证成功，不一致则认证失败

HMAC：一种使用单向散列函数来构造消息认证码的方法
HMAC-SHA-1	HMAC-MD5	HMAC-RIPEMD

存在的问题：
1、密钥配送的问题
2、无法解决第三方证明的问题
3、无法解决防止发送方否认的问题

解决办法：非对称加密的数字签名
*/

/*
使用分析：
接收端和验证端都执行
1、New函数返回一个采用 hash.Hash作为底层 hash接口、key作为密钥的 HMAC算法的 HASH接口
func New(h func() hash.Hash, key []byte) hash.Hash
	--参数1：自己指定的哈希算法，是一个函数
		- md5.New
		- sha1.New
		- sha256.New

	--参数2：密钥
	--返回值：哈希对象

仅在验证端执行
2、比较两个MAC是否相同，而不会泄露对比时间信息。（以规避时间侧信道攻击：指通过计算比较时花费的时间的长短来获取密码的信息，用于密码破解）
func Equal(mac1, mac2 []byte) bool
	--参数：自己计算的哈希值 和 接收到的哈希值
*/

//生成 HMAC (消息验证码)
func GetHmacData(src []byte, key []byte) ([]byte, error) {
	//1、创建哈希器
	hasher := hmac.New(sha256.New, key)

	//2、生成 MAC 值
	_, err := hasher.Write(src)
	if err != nil {
		return nil, err
	}

	mac := hasher.Sum(nil)

	return mac, nil
}

//验证mac
func VerifyHmac(src, key, mac1 []byte) (bool, error) {
	//1、对端接收到的源数据
	//2、对端接收到的MAC1

	//3、对端计算本地的MAC2
	mac2, err := GetHmacData(src, key)
	if err != nil {
		return false, err
	}

	//4、对比MAC1和MAC2
	result := hmac.Equal(mac1, mac2)

	return result, nil
}
