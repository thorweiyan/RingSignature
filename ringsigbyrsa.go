package main
import (
	"crypto/rsa"
	"crypto/sha1"
	"math/rand"
	rand2 "crypto/rand"
	"math/big"
	"fmt"
	"time"
)

type ring struct {
	K []*rsa.PrivateKey
	L uint
	N int
	Q *big.Int
	P *big.Int
}

func (this *ring) init(k []*rsa.PrivateKey, L uint) {
	this.K = make([]*rsa.PrivateKey, 0, len(k))
	this.K = append(this.K, k...)
	this.L = L
	this.N = len(k)
	this.Q = big.NewInt(1)
	this.Q.Lsh(this.Q, L)
	this.P = big.NewInt(0)
}

func (this *ring) sign(m string, z int) []*big.Int{
	this.permut(m)
	s := make([]*big.Int, this.N, this.N)
	e := big.NewInt(0)
	temp := big.NewInt(0)
	c := big.NewInt(0)
	v := big.NewInt(0)
	u := big.NewInt(0)

	var rand1 *rand.Rand
	rand1 = rand.New(rand.NewSource(time.Now().Unix()))
	//应该是要保存的参数
	u.Set(temp.Rand(rand1, this.Q))
	v.Set(this.E(u))
	c.Set(v)
	var loop []int
	for i:=int(0); i < this.N; i++ {
		loop = append(loop, i)
	}
	loop = append(loop, loop...)
	loop = loop[z+1:z+this.N]
	for _,i := range loop {
		s[i] = big.NewInt(0)
		s[i].Set(temp.Rand(rand1, this.Q))
		temp.SetInt64(int64(this.K[i].E))
		e = this.g(s[i], temp, this.K[i].N)
		//fmt.Println(e)
		v = this.E(v.Xor(v,e))
		if (i + 1) % this.N == 0 {
			c.Set(v)
		}
	}
	s[z] = big.NewInt(0)
	s[z].Set(this.g(temp.Xor(v, u), this.K[z].D, this.K[z].N))
	re := []*big.Int{c}
	//fmt.Println(s)
	return append(re, s[:]...)
}

func (this *ring) verify(m string, X []*big.Int) int{
	var y []*big.Int
	r := big.NewInt(0)
	temp := big.NewInt(0)
	this.permut(m)
	//生成所有yi
	for i:=0; i < len(X)-1; i++ {
		temp = big.NewInt(int64(this.K[i].E))
		y = append(y, this.g(X[i+1], temp, this.K[i].N))
		//fmt.Println(this.g(X[i+1], temp, this.K[i].N))
	}
	//一轮过后是否相同，Ckv（y1...yn）=E(yn xor E(yn-1 xor ... E(y1 xor v)...)) = v
	r.Set(X[0])
	for i:=0; i < this.N; i++ {
		r = this.E(temp.Xor(r, y[i]))
	}
	//fmt.Println(r)
	//fmt.Println(X[0])
	return r.Cmp(X[0])
}

//求出明文的hash放入P中作为k
func (this *ring) permut(m string) {
	a := sha1.Sum([]byte(m))
	this.P.SetBytes(a[:])
}

//生成随机数+原本明文hash的hash
func (this *ring) E(x *big.Int) *big.Int {
	msg := x.String() + this.P.String()
	re := big.NewInt(0)
	a := sha1.Sum([]byte(msg))
	return re.SetBytes(a[:])
}

//g的函数，针对传入的e不同功能不同
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


func main() {
	size := 4
	msg1, msg2 := "hello", "world!"
	var key []*rsa.PrivateKey
	r := new(ring)
	for i := 0; i<size; i++{
		new,_ := rsa.GenerateKey(rand2.Reader, 1024)
		key = append(key, new)
	}
	r.init(key, 1024)

	for i := 0; i<size; i++{
		s1 := r.sign(msg1, i)
		s2 := r.sign(msg2, i)
		fmt.Print(i, ":: ")
		fmt.Print(r.verify(msg1, s1), " ")
		fmt.Print(r.verify(msg2, s2), " ")
		fmt.Print(r.verify(msg2, s1))
		fmt.Println()
	}
}

func Sign_Wrapper(size int, num int, msg string, key []*rsa.PrivateKey) []*big.Int{
	r := new(ring)
	r.init(key, 1024)
	return r.sign(msg, num)
}

func Verify_Wrapper(msg string, key []*rsa.PrivateKey, X []*big.Int) bool {
	r := new(ring)
	r.init(key, 1024)
	re := r.verify(msg, X)
	if re == 0 {
		return true
	}else {
		return false
	}
}