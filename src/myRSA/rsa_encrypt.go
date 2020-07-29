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
1、加密的数据都是明文对应的数字值（有一个字符对应表）
2、对数值依次进行 E 次方处理
3、对 N 取模

公钥：{E,N}，由 E,N 组成公钥
E：encrypt（根据特定规则，限定一个区间（f(N)），在这个区间内随机选的）
N:素数的乘积

RSA的安全性基于：对大数 N（素数的乘积）进行因式分解（世界公认难题）
素数（质数）：除了1和本身外，没有能够整除的数，2，3，5，7，11，13，17

1、选择一对不同、足够大的素数 p、q，最好 100-200位的大素数
2、N = p*q
3、f(N)=(p-1)(q-1),p、q要严加保密，不让任何人知道
4、找一个与 f(N)互质的数 E，且 1<E<f(N)
5、再计算 D：使得 DE的乘积 mod f(N)，结果为 1，即：D*E===1 mod f(N)
6、公钥 KU=(E,N)，私钥 KR=(D,N)
7、将明文变换为 0至 N-1的一个整数 M。
8、加密：C === M的 E次方 mod N
9、解密：M === C的 D次方 mod N

P:3,Q=11
N: 3*11=33
F(N)=(3-1)(11-1)=2*10=20
E:1<E<20 ==> 3
(D*E)%F(N) = 1
(D*3) % 20 = 1 ==> 7
公钥：{E,N}={3,33}
私钥：{D,N}={7,33}
*/

//使用公钥进行加密
/*
1、通过公钥文件读取公钥信息 ==> pem encode的数据
2、通过 pem decode 得到block中的der编码数据
3、解码得到公钥
4、使用公钥加密
*/
func RsaEncrypt(filePath string, plainText []byte) ([]byte, error) {
	//1、通过公钥文件读取公钥信息 ==> pem encode的数据
	info, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	//2、通过 pem decode 得到block中的der编码数据
	block, _ := pem.Decode(info) //rest参数是未解码完的数据
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("公钥数据出错")
	}

	//3、解码得到公钥
	derText := block.Bytes
	publicKey, err := x509.ParsePKCS1PublicKey(derText)
	if err != nil {
		return nil, err
	}

	//4、使用公钥加密
	cipherData, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		return nil, err
	}

	return cipherData, nil
}
