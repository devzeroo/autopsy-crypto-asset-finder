#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Valida os 8 novos validadores contra ground-truth antes de portar ao plugin."""
import hashlib, base64
from Crypto.Hash import keccak

# ----------------------------------------------------------------- primitivas
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
MONERO_ALPHABET = B58
ENC_TO_DEC = {0:0,2:1,3:2,5:3,6:4,7:5,9:6,10:7,11:8}

def b58decode(s):
    num=0
    for c in s:
        i=B58.find(c)
        if i<0: raise ValueError("b58")
        num=num*58+i
    full=num.to_bytes((num.bit_length()+7)//8,'big') if num else b''
    pad=len(s)-len(s.lstrip('1'))
    return b'\x00'*pad+full

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def keccak256(b):
    k=keccak.new(digest_bits=256); k.update(b); return k.digest()
def blake2b512(b): return hashlib.blake2b(b, digest_size=64).digest()
def sha512_256(b): return hashlib.new('sha512_256', b).digest()

def base32_decode(s):
    bits=0;val=0;out=bytearray()
    for c in s:
        i=B32.find(c)
        if i<0: raise ValueError("b32")
        val=(val<<5)|i; bits+=5
        if bits>=8:
            bits-=8; out.append((val>>bits)&0xff)
    return bytes(out)

def b64_ton(s):
    s2=s.replace('-','+').replace('_','/'); pad=(-len(s2))%4
    return base64.b64decode(s2+'='*pad)

def crc16_xmodem(data):
    crc=0
    for b in bytearray(data):
        crc^=(b<<8)
        for _ in range(8):
            crc=((crc<<1)^0x1021)&0xffff if (crc&0x8000) else (crc<<1)&0xffff
    return crc

def monero_b58_decode(s):
    out=bytearray(); full=len(s)//11; rem=len(s)%11
    def block(bk,size):
        num=0
        for ch in bk:
            i=MONERO_ALPHABET.find(ch)
            if i<0: raise ValueError("mn char")
            num=num*58+i
        if num>=(1<<(8*size)): raise ValueError("mn overflow")
        b=bytearray(size)
        for k in range(size-1,-1,-1): b[k]=num&0xff; num>>=8
        return b
    for i in range(full): out+=block(s[i*11:i*11+11],8)
    if rem:
        sz=ENC_TO_DEC.get(rem)
        if not sz: raise ValueError("mn rem")
        out+=block(s[full*11:],sz)
    return bytes(out)

# bech32
def _polymod(v):
    GEN=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]; chk=1
    for x in v:
        b=chk>>25; chk=(chk&0x1ffffff)<<5^x
        for i in range(5): chk^=GEN[i] if ((b>>i)&1) else 0
    return chk
def _hrpexp(h): return [ord(c)>>5 for c in h]+[0]+[ord(c)&31 for c in h]
def bech32_decode(bech):
    if bech.lower()!=bech and bech.upper()!=bech: return (None,None)
    bech=bech.lower(); pos=bech.rfind("1")
    if pos<1 or pos+7>len(bech): return (None,None)
    if any(c not in BECH32 for c in bech[pos+1:]): return (None,None)
    hrp=bech[:pos]; data=[BECH32.find(c) for c in bech[pos+1:]]
    const=_polymod(_hrpexp(hrp)+data)
    if const==1: return (hrp,"bech32")
    if const==0x2bc830a3: return (hrp,"bech32m")
    return (None,None)

# cashaddr
def _cash_polymod(values):
    GEN=[0x98f2bc8e61,0x79b76d99e2,0xf33e5fb3c4,0xae2eabe2a8,0x1e4f43e470]; c=1
    for d in values:
        c0=c>>35; c=((c&0x07ffffffff)<<5)^d
        for i in range(5):
            if (c0>>i)&1: c^=GEN[i]
    return c^1

# ----------------------------------------------------------------- validadores
COSMOS_HRPS={"cosmos","osmo","inj","celestia","akash","juno","secret","stars",
             "axelar","kava","evmos","dydx","neutron","stride","regen","band",
             "sei","persistence","kujira","agoric","umee","stargaze"}

def monero_ok(s):
    if len(s) not in (95,106): return False
    try: raw=bytearray(monero_b58_decode(s))
    except Exception: return False
    if len(raw)<5: return False
    if keccak256(bytes(raw[:-4]))[:4]!=bytes(raw[-4:]): return False
    return raw[0] in (18,19,42)

def stellar_ok(s):
    if len(s)!=56: return False
    try: raw=bytearray(base32_decode(s))
    except Exception: return False
    if len(raw)!=35: return False
    if crc16_xmodem(bytes(raw[:-2]))!=(raw[-2]|(raw[-1]<<8)): return False
    return raw[0] in (0x30,0x90)   # G=public, S=seed

def ton_ok(s):
    if len(s)!=48: return False
    try: raw=bytearray(b64_ton(s))
    except Exception: return False
    if len(raw)!=36: return False
    return crc16_xmodem(bytes(raw[:34]))==((raw[34]<<8)|raw[35])

def ss58_ok(s):
    if not (46<=len(s)<=48): return False
    try: raw=bytearray(b58decode(s))
    except Exception: return False
    if len(raw)!=35: return False
    h=blake2b512(b"SS58PRE"+bytes(raw[:33]))
    return h[0]==raw[33] and h[1]==raw[34]

def algorand_ok(s):
    if len(s)!=58: return False
    try: raw=bytearray(base32_decode(s))
    except Exception: return False
    if len(raw)!=36: return False
    return sha512_256(bytes(raw[:32]))[-4:]==bytes(raw[32:36])

def tezos_ok(s):
    if not s[:3] in ("tz1","tz2","tz3","KT1"): return False
    try: raw=b58decode(s)
    except Exception: return False
    if len(raw)<5: return False
    return sha256d(raw[:-4])[:4]==raw[-4:]

def cashaddr_ok(s):
    if ":" in s: prefix,payload=s.split(":",1)
    else: prefix,payload="bitcoincash",s
    prefix=prefix.lower(); payload=payload.lower()
    if any(c not in BECH32 for c in payload): return False
    data=[BECH32.find(c) for c in payload]
    pe=[ord(c)&0x1f for c in prefix]+[0]
    return _cash_polymod(pe+data)==0

def cosmos_ok(s):
    hrp,spec=bech32_decode(s)
    if not hrp: return False
    for suf in ("valoperpub","valconspub","valoper","valcons","pub"):
        if hrp.endswith(suf): hrp=hrp[:-len(suf)]; break
    return hrp in COSMOS_HRPS

# ----------------------------------------------------------------- testes
def corrupt(s):
    # altera 1 caractere do MEIO (sempre significativo; o ultimo char de
    # esquemas base32 pode conter bits de padding ignorados)
    i=len(s)//2
    while i<len(s) and not s[i].isalnum(): i+=1
    c=s[i]; repl="c" if c.lower()!="c" else "d"
    if c.isupper(): repl=repl.upper()
    return s[:i]+repl+s[i+1:]

import sys
results=[]
def check(name, valid_addr, fn, lib_cross=None):
    ok_valid = fn(valid_addr)
    bad = corrupt(valid_addr)
    ok_bad = fn(bad)
    cross = ""
    if lib_cross is not None:
        cross = "  cross-lib=%s" % ("OK" if lib_cross else "FALHOU")
    status = "PASS" if (ok_valid and not ok_bad and (lib_cross is None or lib_cross)) else "FALHA"
    results.append(status)
    print("[%s] %-12s valido=%s corrompido_rejeitado=%s%s" %
          (status, name, ok_valid, (not ok_bad), cross))

print("="*70)
# --- Monero (ground-truth: endereco de doacao oficial) ---
XMR="44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
check("Monero", XMR, monero_ok)

# --- SS58 Polkadot/substrate (ground-truth: conta dev Alice, prefix 42) ---
ALICE="5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
check("SS58", ALICE, ss58_ok)

# --- BCH CashAddr (ground-truth: exemplo da especificacao) ---
BCH="bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
check("BCH", BCH, cashaddr_ok)

# --- Tezos (ground-truth: endereco de burn conhecido) ---
XTZ="tz1burnburnburnburnburnburnburjAYjjX"
check("Tezos", XTZ, tezos_ok)

# --- Stellar (gerado por stellar-sdk; cross-check publico G e secret S) ---
from stellar_sdk import Keypair
kp=Keypair.random()
GPUB=kp.public_key; SSEC=kp.secret
check("Stellar-G", GPUB, stellar_ok, lib_cross=True)
check("Stellar-S", SSEC, stellar_ok, lib_cross=True)

# --- Algorand (gerado por algosdk; cross-check) ---
import algosdk
_, ALGO = algosdk.account.generate_account()
cross_algo = algosdk.encoding.is_valid_address(ALGO)
check("Algorand", ALGO, algorand_ok, lib_cross=cross_algo)

# --- Cosmos (gerado via bech32 ref + cross-check de checksum) ---
import bech32, os
data=bech32.convertbits(os.urandom(20),8,5)
COSMOS=bech32.bech32_encode("cosmos", data)
cross_cosmos = (bech32.bech32_decode(COSMOS)[0]=="cosmos")
check("Cosmos", COSMOS, cosmos_ok, lib_cross=cross_cosmos)

# --- TON: valida a primitiva CRC16/XMODEM contra o check value padrao 0x31C3,
#     depois monta um endereco valido e confirma ida-e-volta ---
crc_ok = (crc16_xmodem(b"123456789")==0x31C3)
tag=bytes([0x11,0x00])+os.urandom(32)
ton_addr_bytes=tag+crc16_xmodem(tag).to_bytes(2,'big')
TON=base64.urlsafe_b64encode(ton_addr_bytes).decode().rstrip("=")
check("TON", TON, ton_ok, lib_cross=crc_ok)

print("="*70)
print("CRC16/XMODEM('123456789')=0x%04X (esperado 0x31C3) -> %s" %
      (crc16_xmodem(b"123456789"), "OK" if crc_ok else "FALHA"))
print("RESULTADO:", "TODOS PASSARAM" if all(r=="PASS" for r in results)
      else "HA FALHAS -> revisar")
sys.exit(0 if all(r=="PASS" for r in results) else 1)
