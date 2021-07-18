package main

import (
	"encoding/json"
	"flag"
	_ "github.com/ing-bank/zkrp"
	"github.com/ing-bank/zkrp/bulletproofs"
	"github.com/wumansgy/goEncrypt"
	"io/ioutil"
	"math/big"
)

var (
	upper  int64
	lower  int64
	secret int64
	Pub    []byte
)

func init() {
	flag.Int64Var(&upper, "ub", 200, "范围验证上界")
	flag.Int64Var(&lower, "lb", 1, "范围验证下界")
	flag.Int64Var(&secret, "s", 50, "隐私数据")
	flag.Parse()

	goEncrypt.GetEccKey()
	Pub, _ = ioutil.ReadFile("eccpublic.pem")
}

func main() {
	Verify(Prove())
}

func Prove() ([]byte, []byte) {

	params, _ := bulletproofs.SetupGeneric(lower, upper)

	bigSecet := new(big.Int).SetInt64(int64(secret))

	proof, _ := bulletproofs.ProveGeneric(bigSecet, params)

	pjson, _ := json.Marshal(proof)

	return pjson, UserSignature(pjson)
}

func UserSignature(msg []byte) []byte {
	Priv, _ := ioutil.ReadFile("eccprivate.pem")

	rtext, stext, err := goEncrypt.EccSign(msg, Priv)
	if err != nil {
		panic(err)
	}
	return append(rtext, stext...)
}

func Verify(proofJson []byte, Sig []byte) bool {
	//What the server do

	//only the json form of the proof is needed for the verifier to do its job

	var decodedProof bulletproofs.ProofBPRP
	_ = json.Unmarshal(proofJson, &decodedProof)

	ok, _ := decodedProof.Verify()

	l := len(Sig)
	ok = ok && goEncrypt.EccVerifySign(proofJson, Pub, Sig[:l/2], Sig[l/2:])

	if ok {
		println("secret verified to be [", lower, ",", upper, ")")
	}

	return ok
}
