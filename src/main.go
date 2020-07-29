package main

import (
	"fmt"
	"github.com/imroc/biu"
	"strings"
)

const publicKeyPath = "data/RSAPublicKey.pem"
const privateKeyPath = "data/RSAPrivateKey.pem"

func main() {
	/*
		DES CBC：
			src := []byte("123456789")
			key := []byte("12345678")

			dst := myDES.DesCbcEncrypt(src, key)
			fmt.Printf("cipherData : %x\n", dst)

			plainText := myDES.DesCbcDecrypt(dst, key)
			fmt.Printf("plainText str : %s\n", plainText)
			fmt.Printf("plainText hex : %x\n", plainText)
	*/

	/*
		AES CTR:
			src := []byte("123456789")
			key := []byte("1234567887654321")

			cipherData := myAES.AesCTREncrypt(src, key)
			fmt.Printf("cipherData : %x\n", cipherData)

			fmt.Println("=================================")

			plainText := myAES.AesCTRDecrypt(cipherData, key)
			fmt.Printf("plainText : %s\n", plainText)
	*/

	/*
		生成RSA密钥
		注：不能分成两个函数，写公钥时重新生成GenerateKey函数会返回新的的私钥
		这时公钥和私钥就不匹配了
			err := myRSA.GenRsaPrivateKey(1024)
			if err != nil{
				panic(err)
			}

			err = myRSA.GenRsaPublicKey(1024)
			if err != nil{
				panic(err)
			}

		err := myRSA.GenRsaKey(1024)
			if err != nil{
				panic(err)
			}
	*/

	/*
		RSA加密解密：
		src := []byte("明晨五点总攻！")
			cipherData, err := myRSA.RsaEncrypt(publicKeyPath, src)
			if err != nil {
				fmt.Println("公钥加密失败: ", err)
			}

			fmt.Printf("cipherData: %x\n", cipherData)

			fmt.Println("++++++++++++++++++++++++++++++++++")
			plainText, err := myRSA.RsaDecrypt(privateKeyPath, cipherData)
			if err != nil {
				fmt.Println("私钥解密出错: ", err)
			}
			fmt.Printf("plainText : %s\n", string(plainText))
	*/

	/*
		Base64编码测试
		fmt.Println("标准的Base64编码测试：")
			info := []byte("国足宇宙第一")

			//base64.StdEncoding.Encode(info,info)
			baseStr := base64.StdEncoding.EncodeToString(info)
			fmt.Printf("base64编码为：%s\n", baseStr)

			baseStr = base64.URLEncoding.EncodeToString(info)
			fmt.Printf("base64 URL 编码为：%s\n", baseStr)
	*/

	/*
		md5 测试
			hashInfo := myEncode.GetMd5Info("hello world")
			fmt.Printf("hash value : %x\n",hashInfo)

			fmt.Println("++++++++++++++++++++++++")

			hashValue := myEncode.GetMd5Data([]byte("hello world"))
			fmt.Printf("hash2 value : %x\n",hashValue)
	*/

	/*
		sha256 测试
			hashValue,err := myEncode.GetSha256Info(privateKeyPath)
			if err != nil{
				panic(err)
			}
			fmt.Printf("hashValue : %x \n",hashValue)
	*/

	/*
		消息认证：
			src := []byte("hello world")
			key := []byte("1234567890")
			mac1,err := myEncode.GetHmacData(src,key)
			if err != nil{
				panic(err)
			}
			fmt.Printf("mac1: %x\n",mac1)

			result,err := myEncode.VerifyHmac(src,key,mac1)
			if err != nil{
				panic(err)
			}
			fmt.Printf("验证结果为：%v \n",result)
	*/

	/*
		数字签名：
			src := []byte("hello world")
			sigData,err := myDS.RsaSignData(privateKeyPath, src)
			if err != nil{
				fmt.Printf("签名失败，err : %s \n", err)
			}
			fmt.Printf("sigData : %x \n",sigData)

			fmt.Println("+++++++++++++++++++++++++++++++")

			err = myDS.VerifySign(publicKeyPath, sigData, src)
			if err != nil{
				fmt.Println("认证失败，err:",err)
			}else {
				fmt.Println("认证成功")
			}
	*/

	data := []uint8{1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0}
	var temp = make([]string, len(data))
	for id, item := range data {
		temp[id] = fmt.Sprintf("%d", item)
	}
	s := strings.Join(temp, "")

	bs := biu.BinaryStringToBytes(s)
	hex := fmt.Sprintf("%x", bs)
	fmt.Println(hex)

}
