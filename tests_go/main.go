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

func EncryptTransaction(msg []byte, pks [][]byte, t uint64, n uint64) ([]byte, error) {
	client := http.Client{}

	req := &api.EncryptRequest{
		Msg: msg,
		Pks: pks,
		T:   t,
		N:   n,
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}

	postReader := bytes.NewReader(data)

	resp, err := client.Post("http://127.0.0.1:8080/encrypt", "application/protobuf", postReader)

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

	var encryptDataResp api.Response
	err = proto.Unmarshal(bodyBytes, &encryptDataResp)
	if err != nil {
		return nil, err
	}

	return encryptDataResp.Result, nil
}

func DecryptTransaction(enc []byte, pks [][]byte, parts [][]byte, sa1 []byte, sa2 []byte, iv []byte, t uint64, n uint64) ([]byte, error) {
	client := http.Client{}

	req := &api.DecryptParamsRequest{
		Enc:   []byte(enc),
		Pks:   pks,
		Parts: parts,
		Sa1:   sa1,
		Sa2:   sa2,
		Iv:    iv,
		T:     t,
		N:     n,
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

func PartialDecrypt(gammaG2 []byte) ([]byte, error) {
	client := http.Client{}

	req := &api.GammaG2Request{
		GammaG2: []byte(gammaG2),
	}
	data, err := proto.Marshal(req)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	postReader := bytes.NewReader(data)

	resp, err := client.Post("http://127.0.0.1:8080/partdec", "application/protobuf", postReader)
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

func GetPK(id uint64, n uint64) ([]byte, error) {
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

	resp, err := client.Post("http://127.0.0.1:8080/getpk", "application/protobuf", postReader)
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

func VerifyPart(pk []byte, gammaG2 []byte, partDec []byte) error {
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

	resp, err := client.Post("http://127.0.0.1:8080/verifydec", "application/protobuf", postReader)
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
	var n uint64 = 32
	var k uint64 = 22
	var t uint64 = 2

	enc, err := os.ReadFile("enc")
	if err != nil {
		fmt.Println("Error reading enc:", err)
		return
	}

	pks := make([][]byte, k)
	sks := make([][]byte, k)
	parts := make([][]byte, k)

	for i := 0; i < int(k); i++ {
		pk, err := os.ReadFile(fmt.Sprintf("pks/%d", i))
		if err != nil {
			fmt.Println("Error reading pk:", err)
			os.Exit(1)
		}
		pks[i] = pk

		sk, err := os.ReadFile(fmt.Sprintf("sks/%d", i))
		if err != nil {
			fmt.Println("Error reading sk:", err)
			os.Exit(1)
		}
		sks[i] = sk

		part, err := os.ReadFile(fmt.Sprintf("parts/%d", i))
		if err != nil {
			fmt.Println("Error reading part:", err)
			os.Exit(1)
		}
		parts[i] = part
	}

	sa1, err := os.ReadFile("sa1")
	if err != nil {
		fmt.Println("Error reading sa1:", err)
		os.Exit(1)
	}

	sa2, err := os.ReadFile("sa2")
	if err != nil {
		fmt.Println("Error reading sa2:", err)
		os.Exit(1)
	}

	gammaG2, err := os.ReadFile("gamma_g2")
	if err != nil {
		fmt.Println("Error reading gamma_g2:", err)
		os.Exit(1)
	}

	iv, err := os.ReadFile("iv")
	if err != nil {
		fmt.Println("Error reading iv:", err)
		os.Exit(1)
	}

	// Change directory
	err = os.Chdir("..")
	if err != nil {
		fmt.Println("Error changing directory:", err)
		os.Exit(1)
	}

	// Run the subprocess
	/*cmd := exec.Command("cargo", "run", "--", "--transcript", "transcript.json", "--bls-key", "tests/sks/12", "--api-port", "8080")
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Start()
	if err != nil {
		fmt.Println("Error starting subprocess:", err)
		return
	}

	// Wait for 15 seconds
	time.Sleep(15 * time.Second)
	*/
	// Verify the parts
	part, err := PartialDecrypt(gammaG2)
	if err != nil {
		fmt.Println("partial decryption failed")
		os.Exit(1)
	}

	for i := 0; i < len(parts[12]); i++ {
		if part[i] != parts[12][i] {
			fmt.Println("failed to decrypt part")
			os.Exit(1)
		}
	}

	for i := 0; i < int(k); i++ {
		err := VerifyPart(pks[i], gammaG2, parts[i])
		if err != nil {
			fmt.Printf("can't verify %d. part\n", i)
			os.Exit(1)
		}
	}

	pk, err := GetPK(12, n)
	if err != nil {
		fmt.Println("partial decryption failed")
		os.Exit(1)
	}

	for i := 0; i < len(pks[12]); i++ {
		if pk[i] != pks[12][i] {
			fmt.Println("failed to decrypt part")
			os.Exit(1)
		}
	}

	// Decrypt
	dec, err := DecryptTransaction(enc, pks, parts, sa1, sa2, iv, t, n)
	if err != nil {
		fmt.Println("can't decrypt transaction")
		os.Exit(1)
	}

	if string(dec) != "Hello, world!" {
		fmt.Println("dec = ", dec)
		os.Exit(1)
	}
}
