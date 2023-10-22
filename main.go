package main

import (
	"fmt"
	"go-cert-manager/pkg/service/csrgenerator"
)

func main() {
	subj := csrgenerator.Subject{
		CommonName: "test.com",
	}

	csr := csrgenerator.NewService(subj)

	privaKey, err := csr.GenPrivateKey()
	if err != nil {
		panic(err)
	}
	pemCSR, err := csr.GenCSR(privaKey)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(pemCSR))
}
