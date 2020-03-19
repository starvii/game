# /usr/bin/python3
# -*- coding: utf8 -*-

"""

"""

import hashlib
import os
import sys
from typing import Optional

PREFIX = b"I_am_the_prefix->|"
SUFFIX = b"|<-I_am_the_suffix"
FLAG = b"sgctf{ef6207dce207f190e2b3475658c058e3}"
KEY = b"This_is_an_very_imp0rt@nt_key!"


def usage():
    print("""python attach.py <execname>""")


def enc() -> bytes:
    # 随机生成密钥
    xor_key: bytes = os.urandom(16)
    print(f"xor_key = {repr(xor_key)}")
    # XOR异或
    en_flag: bytearray = bytearray([b ^ xor_key[i % len(xor_key)] for i, b in enumerate(FLAG)])
    print(f"en_flag = {repr(en_flag)}")
    # 将密钥与密文拼接
    # | xor_key | en_flag |
    xor_key__en_flag: bytes = xor_key + en_flag
    print(f"xor_key_en_flag = {repr(xor_key__en_flag)}")
    # MD5摘要
    md5: bytes = hashlib.md5(xor_key__en_flag).digest()
    print(f"md5 = {repr(md5)}")
    # | md5 | xor_key | en_flag |
    md5__xor_key__en_flag: bytes = md5 + xor_key__en_flag
    print(f"md5__xor_key__en_flag = {repr(md5__xor_key__en_flag)}")
    # 再用预置密钥XOR一遍
    en__md5__xor_key__en_flag: bytes = PREFIX + bytearray(
        [b ^ KEY[i % len(KEY)] for i, b in enumerate(md5__xor_key__en_flag)]) + SUFFIX
    print(f"en__md5__xor_key__en_flag = {repr(en__md5__xor_key__en_flag)}")
    return en__md5__xor_key__en_flag


def dec(endata: bytes) -> Optional[bytes]:
    if not (endata.startswith(PREFIX) and endata.endswith(SUFFIX)):
        return None
    data: bytes = endata[len(PREFIX):-len(SUFFIX)]
    dedata: bytearray = bytearray([b ^ KEY[i % len(KEY)] for i, b in enumerate(data)])
    md5: bytes = dedata[:16]
    if hashlib.md5(dedata[16:]).digest() != md5:
        print("md5 check failed")
        return None
    xorkey: bytes = dedata[16:32]
    enflag: bytes = dedata[32:]
    flag: bytearray = bytearray([b ^ xorkey[i % len(xorkey)] for i, b in enumerate(enflag)])
    return bytes(flag)


def main():
    if len(sys.argv) != 2:
        usage()
        exit()
    fc: bytes = open(sys.argv[1], "rb").read()
    prefix: int = fc.rfind(PREFIX)
    suffix: int = fc.rfind(SUFFIX)
    with_flag: bool = True
    if prefix + len(PREFIX) + 32 < suffix:
        data: bytes = fc[prefix: suffix + len(SUFFIX)]
        print("attached flag maybe exist. try to extract ...")
        flag: Optional[bytes] = dec(data)
        if flag is not None:
            print(f"flag in file '{sys.argv[1]}' is {repr(flag)}")
        else:
            with_flag = False
    else:
        with_flag = False
    if not with_flag:
        with_flag = input(f"attach flag with file '{sys.argv[1]}'(Y/n)?").lower()[0] == "y"
        if with_flag:
            attach_data: bytes = enc()
            data: bytes = fc + attach_data
            open(sys.argv[1] + "-flag", "wb").write(data)


if __name__ == "__main__":
    main()
