package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/korayakpinar/threshold-encryption/api"
	"google.golang.org/protobuf/proto"
)

func EncryptTransaction(msg []byte, pks [][]byte, t uint64, n uint64, url string) (api.EncryptResponse, error) {
	client := http.Client{}
	var encryptDataResp api.EncryptResponse

	req := &api.EncryptRequest{
		Msg: msg,
		Pks: pks,
		T:   t,
		N:   n,
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return encryptDataResp, err
	}

	postReader := bytes.NewReader(data)

	resp, err := client.Post(url, "application/protobuf", postReader)

	if err != nil {
		return encryptDataResp, err
	}

	if resp.StatusCode == 400 {
		return encryptDataResp, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return encryptDataResp, err
	}

	err = proto.Unmarshal(bodyBytes, &encryptDataResp)
	if err != nil {
		return encryptDataResp, err
	}

	return encryptDataResp, nil
}

func DecryptTransaction(enc []byte, pks [][]byte, parts map[uint64]([]byte), gamma_g2 []byte, sa1 []byte, sa2 []byte, iv []byte, t uint64, n uint64) ([]byte, error) {
	client := http.Client{}

	req := &api.DecryptRequest{
		Enc:     []byte(enc),
		Pks:     pks,
		Parts:   parts,
		GammaG2: gamma_g2,
		Sa1:     sa1,
		Sa2:     sa2,
		Iv:      iv,
		T:       t,
		N:       n,
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}

	postReader := bytes.NewReader(data)

	resp, err := client.Post("http://127.0.0.1:8080/decrypt", "application/protobuf", postReader)

	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var decryptDataResp api.Response
	err = proto.Unmarshal(bodyBytes, &decryptDataResp)
	if err != nil {
		return nil, err
	}

	return decryptDataResp.Result, nil
}

func PartialDecrypt(gammaG2 []byte, url string) ([]byte, error) {
	client := http.Client{}

	req := &api.PartDecRequest{
		GammaG2: []byte(gammaG2),
	}
	data, err := proto.Marshal(req)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	postReader := bytes.NewReader(data)

	resp, err := client.Post(url, "application/protobuf", postReader)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	if resp.StatusCode != 200 {
		fmt.Println(err)
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	var partDecResp api.Response
	err = proto.Unmarshal(bodyBytes, &partDecResp)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return partDecResp.Result, nil
}

func GetPK(id uint64, n uint64, url string) ([]byte, error) {
	client := http.Client{}

	req := &api.PKRequest{
		Id: id,
		N:  n,
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}

	postReader := bytes.NewReader(data)

	resp, err := client.Post(url, "application/protobuf", postReader)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	var partDecResp api.Response
	err = proto.Unmarshal(bodyBytes, &partDecResp)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return partDecResp.Result, nil
}

func VerifyPart(pk []byte, gammaG2 []byte, partDec []byte, url string) error {
	client := http.Client{}

	req := &api.VerifyPartRequest{
		Pk:      []byte(pk),
		GammaG2: []byte(gammaG2),
		PartDec: []byte(partDec),
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return err
	}

	postReader := bytes.NewReader(data)

	resp, err := client.Post(url, "application/protobuf", postReader)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return err
	}
	resp.Body.Close()

	return nil
}

func main() {
	var n uint64 = 2
	var k uint64 = 1
	var t uint64 = 1

	expected := "Hello, world!"

	total := time.Now()

	pks := make([][]byte, k)
	ti := time.Now()
	pk, err := GetPK(0, n, "http://127.0.0.1:8080/getpk")
	fmt.Println("getpk", time.Since(ti))
	if err != nil {
		fmt.Println("can't get pk", err)
		os.Exit(1)
	}
	pks[0] = pk

	ti = time.Now()
	enc, err := EncryptTransaction([]byte(expected), pks, t, n, "http://127.0.0.1:8080/encrypt")
	fmt.Println("encrypt", time.Since(ti))
	if err != nil {
		fmt.Println("can't encrypt transaction", err)
		os.Exit(1)
	}

	parts := make([][]byte, k)

	ti = time.Now()
	part, err := PartialDecrypt(enc.GammaG2, "http://127.0.0.1:8080/partdec")
	fmt.Println("partdec", time.Since(ti))
	if err != nil {
		fmt.Println("can't get part", err)
		os.Exit(1)
	}

	ti = time.Now()
	err = VerifyPart(pks[0], enc.GammaG2, part, "http://127.0.0.1:8080/verifydec")
	fmt.Println("verifypart", time.Since(ti))
	if err != nil {
		fmt.Println("can't verify part", err)
		os.Exit(1)
	}
	parts[0] = part

	new_parts := make(map[uint64]([]byte))
	new_parts[0] = parts[0]

	ti = time.Now()
	dec, err := DecryptTransaction(enc.Enc, pks, new_parts, enc.GammaG2, enc.Sa1, enc.Sa2, enc.Iv, t, n)
	fmt.Println("decrypt", time.Since(ti))

	fmt.Println("total time elapsed", time.Since(total))

	if err != nil {
		fmt.Println("can't decrypt transaction", err)
		os.Exit(1)
	}

	if string(dec) != expected {
		fmt.Println("can't decrypt the data", string(dec))
		os.Exit(1)
	}
}
