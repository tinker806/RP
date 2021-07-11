package main

import (
	"encoding/json"
	_ "github.com/ing-bank/zkrp"
	"flag"
	"github.com/ing-bank/zkrp/bulletproofs"
	"math/big"
)

var(
	upper int64
	lower int64
	secret  int64
)

func init() {
	flag.Int64Var(&upper,"ub",200,"范围验证上界")
	flag.Int64Var(&lower,"lb",1,"范围验证下界")
	flag.Int64Var(&secret,"s",50,"隐私数据")
	flag.Parse()
}


func main(){
	params, _ := bulletproofs.SetupGeneric(lower, upper)

	bigSecet := new(big.Int).SetInt64(int64(secret))

	proof, _ := bulletproofs.ProveGeneric(bigSecet, params)

	jsonEncoded,  _ := json.Marshal(proof)

	Verify(jsonEncoded)

}

func Verify(proofJson []byte) bool{
	var decodedProof bulletproofs.ProofBPRP
	_ = json.Unmarshal(proofJson, &decodedProof)

	ok, _ := decodedProof.Verify()

	if ok {
		println("secret verified to be [", lower,",",upper,")")
	}

	return ok
}
