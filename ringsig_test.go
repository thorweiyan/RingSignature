package main


import (
	"crypto/rand"
	"testing"
	"crypto/rsa"
	"fmt"
)

func TestRing(t *testing.T) {
	var key []*rsa.PrivateKey
	var pubkeys []*rsa.PublicKey
	size := 4
	msg1 := "this is a test message!"
	msg2 := "this is another test message!"
	for i := 0; i<size; i++{
		new,_ := rsa.GenerateKey(rand.Reader, 1024)
		key = append(key, new)
		pubkeys = append(pubkeys,&new.PublicKey)
	}
	//SignWrapper传入组成员的个数，签名者在组中的位置（0开头），消息，组成员的公钥，签名者的私钥
	signresult1 := SignWrapper(size, 0, msg1, pubkeys, key[0])
	signresult2 := SignWrapper(size, 1, msg2, pubkeys, key[1])
	//VerifyWrapper传入消息，组成员的公钥
	fmt.Println("msg1 for sign1::" , VerifyWrapper(msg1, pubkeys, signresult1))
	fmt.Println("msg2 for sign2::" , VerifyWrapper(msg2, pubkeys, signresult2))
	fmt.Println("msg2 for sign2(change order)::" , VerifyWrapper(msg2, append(pubkeys[2:], pubkeys[:2]...), signresult2))
	fmt.Println("msg1 for sign2(change msg)::" , VerifyWrapper(msg1, pubkeys, signresult2))
}
