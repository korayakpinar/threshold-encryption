from typing import List, ByteString
import subprocess
import random
import time
import os

import requests
import message_pb2


def partdec_test(
    parts: List[ByteString],
    gamma_g2: ByteString
) -> bool:
    # set 24 ~/.sk
    m = message_pb2.GammaG2Proto()
    m.gamma_g2 = gamma_g2
    
    resp = requests.post("http://127.0.0.1:8080/partdec", headers={'Content-Type': 'application/protobuf'}, data=m.SerializeToString())
    res = message_pb2.ResultProto()
    r = res.ParseFromString(resp.content)
    return res.result == parts[12]


def verifypart_test(pk: ByteString, gamma_g2: ByteString, part_dec: ByteString) -> bool:
    m = message_pb2.VerifyPartProto()
    m.pk = pk
    m.gamma_g2 = gamma_g2
    m.part_dec = part_dec

    resp = requests.post("http://127.0.0.1:8080/verifydec", headers={'Content-Type': 'application/protobuf'}, data=m.SerializeToString())
    return resp.status_code == 200


def decrypt_test(
    enc: ByteString,
    pks: List[ByteString],
    parts: List[ByteString],
    sa1: ByteString,
    sa2: ByteString,
    iv: ByteString,
    t: int,
    n: int
) -> bool:
    m = message_pb2.DecryptParamsProto()
    m.enc = enc
    m.pks[:] = pks
    m.parts[:] = parts
    m.sa1 = sa1
    m.sa2 = sa2
    m.iv = iv
    m.t = t
    m.n = n

    decrypted_data = b"Hello, world!"

    resp = requests.post("http://127.0.0.1:8080/decrypt", headers={'Content-Type': 'application/protobuf'}, data=m.SerializeToString())
    res = message_pb2.ResultProto()
    r = res.ParseFromString(resp.content)
    return res.result == decrypted_data


def main() -> None:
    n = 32
    k = 22
    t = 2

    enc = b""
    with open("enc", "rb") as f:
        enc = f.read()

    pks = []
    sks = []
    parts = []
    for i in range(k):
        with open(f"pks/{i}", "rb") as f:
            pks.append(f.read())

        with open(f"sks/{i}", "rb") as f:
            sks.append(f.read())

        with open(f"parts/{i}", "rb") as f:
            parts.append(f.read())

    sa1 = b""
    with open("sa1", "rb") as f:
        sa1 = f.read()

    sa2 = b""
    with open("sa2", "rb") as f:
        sa2 = f.read()

    gamma_g2 = b""
    with open("gamma_g2", "rb") as f:
        gamma_g2 = f.read()

    iv = b""
    with open("iv", "rb") as f:
        iv = f.read()

    #os.chdir("..")
    #proc = subprocess.Popen(["cargo", "run"])
    #time.sleep(30)
    #os.chdir("tests")

    assert(partdec_test(parts, gamma_g2) == True)

    for i in range(k):
        assert(verifypart_test(pks[i], gamma_g2, parts[i]) == True)

    assert(decrypt_test(enc, pks, parts, sa1, sa2, iv, t, n) == True)


if __name__ == "__main__":
    main()