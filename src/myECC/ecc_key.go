package myECC

/*
ECC椭圆曲线密码：相比RSA使用更小的密钥，提供更高等级的安全
依赖：解决椭圆曲线离散对数问题的困难性
ECC 164位的密钥产生的安全级别相当于RSA 1024位密钥提供的保密强度。

原理：不管是RSA还是ECC，公钥加密算法都是依赖于某个正向计算很简单（多项式时间复杂度）
而逆向计算很难（指数级时间复杂度）的数学问题
1、准备一条曲线
	-P224
	-P256
数字越大，曲线取值空间越大，越安全
2、随意选择曲线上一点P，作一条直线，与曲线相交于Q点和G点
P+Q+G=0	==> P+Q=-G,如果P和Q相同，即2P=-G
当P和Q相同时，求出的-G就是对P点的切线与曲线的交点
3、
*/
