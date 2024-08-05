package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"

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
	var n uint64 = 4
	var k uint64 = 3
	var t uint64 = 2

	expected := "Hello, world!"

	pks := make([][]byte, k)
	j := 8080
	for i := 0; i < int(k); i++ {
		pk, err := GetPK(uint64(i), n, fmt.Sprintf("http://127.0.0.1:%d/getpk", j))
		if err != nil {
			fmt.Println("can't get pk", err)
			os.Exit(1)
		}
		file, err := os.Open(fmt.Sprintf("../keys/%d-pk", i+1))
		if err != nil {
			fmt.Println("can't open file", err)
			os.Exit(1)
		}
		z := make([]byte, 1024)
		_, err = file.Read(z)
		for w := 0; w < len(pk); w++ {
			if pk[w] != z[w] {
				fmt.Println("pk is wrong")
				os.Exit(1)
			}
		}
		if err != nil {
			fmt.Println("can't read file", err)
			os.Exit(1)
		}
		pks[i] = pk
		j++
	}

	enc, err := EncryptTransaction([]byte(expected), pks, t, n, "http://127.0.0.1:8080/encrypt")

	if err != nil {
		fmt.Println("can't encrypt transaction")
		os.Exit(1)
	}

	parts := make([][]byte, n)
	j = 8080

	for i := 0; i < int(k); i++ {
		part, err := PartialDecrypt(enc.GammaG2, fmt.Sprintf("http://127.0.0.1:%d/partdec", j))
		if err != nil {
			fmt.Println("can't get part")
			os.Exit(1)
		}
		err = VerifyPart(pks[i], enc.GammaG2, part, "http://127.0.0.1:8080/verifydec")
		if err != nil {
			fmt.Println("can't verify part")
			os.Exit(1)
		}
		parts[i] = part
		j++
	}

	new_parts := make(map[uint64]([]byte))
	new_parts[0] = parts[0]
	new_parts[2] = parts[2]

	dec, err := DecryptTransaction(enc.Enc, pks, new_parts, enc.GammaG2, enc.Sa1, enc.Sa2, enc.Iv, t, n)

	if err != nil {
		fmt.Println("can't decrypt transaction")
		os.Exit(1)
	}

	if string(dec) != expected {
		fmt.Println("can't decrypt the data")
		os.Exit(1)
	}

}
