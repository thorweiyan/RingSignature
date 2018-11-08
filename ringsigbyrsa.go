package main
import (
	"crypto/rsa"
	"crypto/sha256"
	"math/rand"
	"math/big"
	"time"
)

type ring struct {
	PubKeys []*rsa.PublicKey
	PriKey	*rsa.PrivateKey
	L       uint				//rsa 密钥长度
	N       int					//组成员个数
	Q       *big.Int			//与密钥长度相对应的随机数阈值
	P       *big.Int			//作为对称加密key的hash结果
}

//L是rsa密钥长度
func (this *ring) init(pubkeys []*rsa.PublicKey,prikey *rsa.PrivateKey, L uint) {
	this.PubKeys = make([]*rsa.PublicKey, 0, len(pubkeys))
	this.PubKeys = append(this.PubKeys, pubkeys...)
	this.PriKey = prikey
	this.L = L
	this.N = len(pubkeys)
	this.Q = big.NewInt(1)
	this.Q.Lsh(this.Q, L)
	this.P = big.NewInt(0)
}

//m是消息，z是密钥对应的公钥在环成员的位置，从0开始
func (this *ring) sign(m string, z int) []*big.Int{
	this.hash(m)
	//xs保存的是所有x的值
	xs := make([]*big.Int, this.N, this.N)
	temp := big.NewInt(0)
	c := big.NewInt(0)
	v := big.NewInt(0)
	u := big.NewInt(0)

	var rand1 *rand.Rand
	rand1 = rand.New(rand.NewSource(time.Now().Unix()))
	//pick random v, c=eEk(u), u = myY xor v
	u.Set(temp.Rand(rand1, this.Q))
	v.Set(this.eEk(u))
	c.Set(v)

	//loop 得到签名成员之后的成员顺序
	var loop []int
	for i:=int(0); i < this.N; i++ {
		loop = append(loop, i)
	}
	loop = append(loop, loop...)
	loop = loop[z+1:z+this.N]
	//随机选取E
	for _,i := range loop {
		xs[i] = big.NewInt(0)
		xs[i].Set(temp.Rand(rand1, this.Q))
		temp.SetInt64(int64(this.PubKeys[i].E))
		yi := this.g(xs[i], temp, this.PubKeys[i].N)
		v = this.eEk(v.Xor(v,yi))
		if (i + 1) % this.N == 0 {
			c.Set(v)
		}
	}

	//cal myX from myY
	xs[z] = big.NewInt(0)
	xs[z].Set(this.g(temp.Xor(v, u), this.PriKey.D, this.PriKey.N))
	//re为最后一名成员得到的v
	re := []*big.Int{c}
	return append(re, xs[:]...)
}

func (this *ring) verify(m string, X []*big.Int) int{
	var y []*big.Int
	r := big.NewInt(0)
	temp := big.NewInt(0)
	this.hash(m)
	//生成所有yi
	for i:=0; i < len(X)-1; i++ {
		temp = big.NewInt(int64(this.PubKeys[i].E))
		y = append(y, this.g(X[i+1], temp, this.PubKeys[i].N))
	}
	//一轮过后是否相同，Ckv（y1...yn）=eEk(yn xor eEk(yn-1 xor ... eEk(y1 xor v)...)) = v
	r.Set(X[0])
	for i:=0; i < this.N; i++ {
		r = this.eEk(temp.Xor(r, y[i]))
	}
	return r.Cmp(X[0])
}

//求出明文的hash放入P中作为k，更新成sha256
func (this *ring) hash(m string) {
	a := sha256.Sum256([]byte(m))
	this.P.SetBytes(a[:])
}

//对称加密函数，在这里使用单向hash
func (this *ring) eEk(x *big.Int) *big.Int {
	msg := x.String() + this.P.String()
	re := big.NewInt(0)
	a := sha256.Sum256([]byte(msg))
	return re.SetBytes(a[:])
}

//g的函数，针对传入的e不同功能不同，实现限门函数作用，但不引入随机数
func (this *ring) g(x *big.Int,e *big.Int,n *big.Int) *big.Int{
	temp1 := big.NewInt(0)
	temp2 := big.NewInt(0)
	temp3 := big.NewInt(0)
	temp4 := big.NewInt(0)
	q := big.NewInt(0)
	r := big.NewInt(0)
	q,r = temp1.DivMod(x, n, temp2)
	rslt := big.NewInt(0)
	one := big.NewInt(1)
	temp3.Add(q, one)
	temp3.Mul(temp3, n)
	temp4.Lsh(one, this.L)
	temp4.Sub(temp4, one)
	if temp3.Cmp(temp4) <= 0 {
		rslt.Mul(q, n)
		temp3.Exp(r, e, n)
		rslt.Add(rslt, temp3)
	}else {
		rslt = x
	}
	return rslt
}

func SignWrapper(size int, num int, msg string, key []*rsa.PublicKey, mySecret *rsa.PrivateKey) []*big.Int{
	r := new(ring)
	r.init(key, mySecret,1024)
	return r.sign(msg, num)
}

func VerifyWrapper(msg string, key []*rsa.PublicKey, X []*big.Int) bool {
	r := new(ring)
	r.init(key,nil, 1024)
	re := r.verify(msg, X)
	if re == 0 {
		return true
	}else {
		return false
	}
}