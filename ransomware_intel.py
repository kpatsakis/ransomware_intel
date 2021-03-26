#!/usr/bin/env python3
# coding: utf-8

import subprocess
import sys
import json
import coinaddr
import os
import re
import socket
import os
from p_tqdm import p_map
import pefile
import hashlib
import ssdeep
import tlsh
import magic
from richpe import get_richpe
import math
from collections import Counter


def entropy(data):
    H = 0
    counter = Counter(data)
    l = len(data)
    for cnt in counter.values():
        p = cnt / l
        H += - p * math.log2(p)
    return H


def is_IP(x):
    try:
        a = socket.inet_aton(x)
        return True
    except:
        return False


def scan(pth, outf=""):
    if os.path.isdir(pth):
        res = proc_dir(pth)
    elif os.path.isfile(pth):
        res = proc_file(pth)
    else:
        res = {"Error": "No such file or directory."}
    if len(outf) > 0:
        with open(outf, "w") as f:
            f.write(json.dumps(res))
        return True
    else:
        return res


url_re = re.compile(
    r"((https?):((//)|(\\\\))+[\w\d:#@%/;$()~_?\+-=\\\.&]*)", re.MULTILINE | re.UNICODE)
mail_re = re.compile('^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$')
ip_re = re.compile(
    "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$")
coinsres = {
    "btc": re.compile("[13][a-km-zA-HJ-NP-Z1-9]{25,34}"),
    "bch": re.compile("(bitcoincash:)?(q|p)[a-z0-9]{41}|(BITCOINCASH:)?(Q|P)[A-Z0-9]{41}"),
    "dash": re.compile("X[1-9A-HJ-NP-Za-km-z]{33}"),
    "etc": re.compile("0x[a-fA-F0-9]{40}"),
    "xrp": re.compile("r[0-9a-zA-Z]{24,34}"),
    "ltc": re.compile("[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}"),
    "doge": re.compile("D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}"),
    "neo": re.compile("A[0-9a-zA-Z]{33}"),
    "xmr": re.compile("4[0-9AB][0-9a-zA-Z]{93,104}")
}

__floss_location__ = "./floss"


def proc_dir(pth):
    files2check = []
    directory = os.fsencode(pth)
    for file in os.listdir(pth):
        filename = os.fsdecode(file)
        if not filename.endswith(".json"):
            files2check.append(os.path.join(pth, filename))
    results = p_map(proc_file, files2check)
    return {"results": results}


def proc_file(fname, tm=10):
    coin_dict = {f"{c}": [] for c in coinsres.keys()}
    coin_dict["has_coins"] = False
    res = {"coins": coin_dict}
    cmd = f'{__floss_location__} {fname} -q --output-json {fname}.json 2> /dev/null'
    try:
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        process.wait(timeout=tm)
        with open(f"{fname}.json") as f:
            data = json.loads(f.read())
        strs = []
        for str_cat in data["strings"].keys():
            strs += data["strings"][str_cat]
        res["timeout"] = False
    except:
        process = subprocess.run(['strings', fname], stdout=subprocess.PIPE)
        strs = process.stdout.split(b"\n")
        strs = map(str, strs)
        res["timeout"] = True
    res["name"] = fname
    res["urls"] = []
    res["mails"] = []
    res["IPs"] = []
    with open(fname, "rb") as f:
        data = f.read()
    res["md5"] = hashlib.md5(data).hexdigest()
    res["sha256"] = hashlib.sha256(data).hexdigest()
    res["ssdeep"] = ssdeep.hash(data)
    res["tlshash"] = tlsh.hash(data)
    res["rich"] = get_richpe(fname)
    res["entropy"] = entropy(data)
    if res["rich"] is None:
        res["rich"] = ""
    fmagic = magic.Magic(mime=True, uncompress=True)
    res["magic"] = fmagic.from_file(fname)

    try:
        pe = pefile.PE(fname)
        res["imphash"] = pe.get_imphash()
    except:
        res["imphash"] = ""
    for s in strs:
        if ip_re.match(s):
            res["IPs"].append(s)
        elif url_re.match(s):
            res["urls"].append(s)
        elif mail_re.match(s):
            res["mails"].append(s)
        else:
            for coin in coinsres:
                if coinsres[coin].match(s):
                    try:
                        a = coinaddr.validate(coin, s.encode())
                        if a.valid:
                            res["coins"][coin].append(s)
                            res["coins"]["has_coins"] = True
                    except:
                        pass
    if os.path.exists(f"{fname}.json"):
        os.remove(f"{fname}.json")
    return res


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Please add file or directory to scan")
        sys.exit(1)
    print(scan(sys.argv[1]))
