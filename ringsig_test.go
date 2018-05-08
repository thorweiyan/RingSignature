package main


import (
	"crypto/rand"
	"testing"
	"crypto/rsa"
	"fmt"
)

func TestRing(t *testing.T) {
	var key []*rsa.PrivateKey
	size := 4
	msg1 := "this is a test message!"
	msg2 := "this is another test message!"
	for i := 0; i<size; i++{
		new,_ := rsa.GenerateKey(rand.Reader, 1024)
		key = append(key, new)
	}

	signresult0 := Sign_Wrapper(size, 0, msg1, key)
	signresult1 := Sign_Wrapper(size, 1, msg2, key)

	fmt.Println("msg1 for sign0::" , Verify_Wrapper(msg1, key, signresult0))
	fmt.Println("msg2 for sign1::" , Verify_Wrapper(msg2, key, signresult1))
	fmt.Println("msg1 for sign1::" , Verify_Wrapper(msg1, key, signresult1))
}
