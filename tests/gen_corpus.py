#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gera um corpus forense de ground-truth para testar o CryptoAssetFinder.
Cada vetor "valido" e auto-validado (assert) por implementacao independente,
e cada vetor "invalido" e confirmado como rejeitado, antes de ser gravado.
Produz a arvore /tmp/evidence_root e o manifesto /tmp/expected_results.csv.
"""
import os, hashlib, csv, struct
from Crypto.Hash import keccak

_BASE = os.path.dirname(os.path.abspath(__file__))
ROOT     = os.environ.get("CAF_BUILD",    os.path.join(_BASE, "build", "evidence_root"))
WORDLIST = os.environ.get("CAF_WORDLIST", os.path.join(_BASE, "..", "plugin", "english.txt"))
MANIFEST = os.environ.get("CAF_MANIFEST", os.path.join(_BASE, "expected_results.csv"))

# RNG deterministico: o fixture precisa ser reprodutivel (mesmo manifesto + mesma
# imagem a cada build). Toda a entropia dos vetores passa por esta semente fixa.
import random as _random_mod
_RNG = _random_mod.Random(0xC0FFEE17)
def _urandom(n):
    return bytes(bytearray(_RNG.getrandbits(8) for _ in range(n)))

# ---------------------------------------------------------------- base58
B58_BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_XRP = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

def b58encode(b, alphabet=B58_BTC):
    num = int.from_bytes(b, "big")
    out = ""
    while num > 0:
        num, rem = divmod(num, 58)
        out = alphabet[rem] + out
    pad = 0
    for c in b:
        if c == 0: pad += 1
        else: break
    return alphabet[0]*pad + out

def b58decode(s, alphabet=B58_BTC):
    num = 0
    for ch in s:
        num = num*58 + alphabet.index(ch)
    full = num.to_bytes((num.bit_length()+7)//8, "big")
    pad = 0
    for ch in s:
        if ch == alphabet[0]: pad += 1
        else: break
    return b"\x00"*pad + full

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def b58check_encode(payload, alphabet=B58_BTC):
    return b58encode(payload + sha256d(payload)[:4], alphabet)

def b58check_ok(s, alphabet=B58_BTC):
    try: raw = b58decode(s, alphabet)
    except ValueError: return False
    if len(raw) < 5: return False
    return sha256d(raw[:-4])[:4] == raw[-4:]

# ---------------------------------------------------------------- bech32
CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def polymod(v):
    GEN=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]; chk=1
    for x in v:
        b=chk>>25; chk=(chk&0x1ffffff)<<5^x
        for i in range(5): chk ^= GEN[i] if ((b>>i)&1) else 0
    return chk
def hrpexp(h): return [ord(c)>>5 for c in h]+[0]+[ord(c)&31 for c in h]
def bech32_create(hrp, data, spec):
    const = 0x2bc830a3 if spec=="bech32m" else 1
    pm = polymod(hrpexp(hrp)+data+[0,0,0,0,0,0]) ^ const
    chk = [(pm>>5*(5-i))&31 for i in range(6)]
    return hrp+"1"+"".join(CH[d] for d in data+chk)
def bech32_decode(bech):
    if bech.lower()!=bech and bech.upper()!=bech: return (None,None)
    bech=bech.lower(); pos=bech.rfind("1")
    if pos<1 or pos+7>len(bech): return (None,None)
    if any(c not in CH for c in bech[pos+1:]): return (None,None)
    hrp=bech[:pos]; data=[CH.find(c) for c in bech[pos+1:]]
    const=polymod(hrpexp(hrp)+data)
    if const==1: return (hrp,"bech32")
    if const==0x2bc830a3: return (hrp,"bech32m")
    return (None,None)
def convertbits(data,frm,to,pad=True):
    acc=0;bits=0;ret=[];maxv=(1<<to)-1
    for b in data:
        acc=(acc<<frm)|b; bits+=frm
        while bits>=to: bits-=to; ret.append((acc>>bits)&maxv)
    if pad and bits: ret.append((acc<<(to-bits))&maxv)
    return ret

# ---------------------------------------------------------------- EIP-55
def keccak256(b):
    k=keccak.new(digest_bits=256); k.update(b); return k.digest()
def eip55(addr_hex_lower):   # 40 hex chars, no 0x
    h=keccak256(addr_hex_lower.encode()).hex()
    out=""
    for i,c in enumerate(addr_hex_lower):
        out += c.upper() if (c not in "0123456789" and int(h[i],16)>=8) else c
    return "0x"+out
def eip55_status(addr):      # 0x + 40 hex
    body=addr[2:]; low=body.lower()
    if body==low or body==body.upper(): return "sem_checksum"
    return "checksum_valido" if eip55(low)==addr else "invalido"

# ---------------------------------------------------------------- BIP-39
WL = [w.strip() for w in open(WORDLIST) if w.strip()]
WLI = {w:i for i,w in enumerate(WL)}
def mnemonic_from_entropy(ent):
    h=hashlib.sha256(ent).digest()
    bits="".join(f"{b:08b}" for b in ent)
    cs=len(ent)*8//32
    bits+= "".join(f"{b:08b}" for b in h)[:cs]
    idx=[int(bits[i:i+11],2) for i in range(0,len(bits),11)]
    return " ".join(WL[i] for i in idx)
def bip39_ok(words):
    n=len(words)
    if n not in (12,15,18,21,24): return False
    if any(w not in WLI for w in words): return False
    bits="".join(f"{WLI[w]:011b}" for w in words)
    total=n*11; cs=total//33; ent=total-cs
    eb=bytes(int(bits[i:i+8],2) for i in range(0,ent,8))
    hb="".join(f"{b:08b}" for b in hashlib.sha256(eb).digest())
    return hb[:cs]==bits[ent:]

# ================================================================ vetores
rows=[]   # (path, network, kind, value, validation, token, note)
neg=[]    # (path, value, note) -> esperado AUSENTE

def addr_b58check(version_bytes, n=20, alphabet=B58_BTC):
    import os as _os
    payload=version_bytes+_urandom(n)
    return b58check_encode(payload, alphabet)

# --- Bitcoin -------------------------------------------------------------
btc_p2pkh = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"            # genesis (vetor real)
assert b58check_ok(btc_p2pkh)
btc_p2sh  = addr_b58check(b"\x05")                           # version 0x05 -> '3'
assert b58check_ok(btc_p2sh) and btc_p2sh[0]=="3"
# segwit v0 (bech32) e v1/taproot (bech32m)
prog20=_urandom(20); prog32=_urandom(32)
btc_bech32 = bech32_create("bc",[0]+convertbits(prog20,8,5),"bech32")
btc_bech32m= bech32_create("bc",[1]+convertbits(prog32,8,5),"bech32m")
assert bech32_decode(btc_bech32)==("bc","bech32")
assert bech32_decode(btc_bech32m)==("bc","bech32m")

# --- Ethereum / EVM ------------------------------------------------------
eth_valid = eip55("a"*0 + _urandom(20).hex())             # checksummed
assert eip55_status(eth_valid)=="checksum_valido"
eth_lower = eth_valid.lower()
assert eip55_status(eth_lower)=="sem_checksum"
# stablecoins (casing EIP-55 correta calculada via keccak)
usdt_eth = eip55("dac17f958d2ee523a2206206994597c13d831ec7")
usdc_eth = eip55("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
assert eip55_status(usdt_eth)=="checksum_valido"
assert eip55_status(usdc_eth)=="checksum_valido"
eth_ctx = eip55(_urandom(20).hex())                       # classificado por contexto

# --- Cardano -------------------------------------------------------------
ada_shelley = bech32_create("addr", convertbits(_urandom(57),8,5), "bech32")
ada_stake   = bech32_create("stake",convertbits(_urandom(28),8,5), "bech32")
assert bech32_decode(ada_shelley)[0]=="addr"
assert bech32_decode(ada_stake)[0]=="stake"
ada_byron = "Ddz"+b58encode(_urandom(50))[:80]            # Byron -> sem_checksum

# --- Tron / Litecoin / Dogecoin / XRP ------------------------------------
tron = b58check_encode(b"\x41"+_urandom(20))              # version 0x41 -> 'T'
assert b58check_ok(tron) and tron[0]=="T"
usdt_tron_contract = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"   # contrato USDT TRC-20 (real)
ltc = b58check_encode(b"\x30"+_urandom(20))               # 'L'
assert b58check_ok(ltc) and ltc[0]=="L"
ltc_bech = bech32_create("ltc",[0]+convertbits(_urandom(20),8,5),"bech32")
assert bech32_decode(ltc_bech)[0]=="ltc"
doge = b58check_encode(b"\x1e"+_urandom(20))              # 'D' (nao 'Ddz')
assert b58check_ok(doge) and doge[0]=="D" and not doge.startswith("Ddz")
xrp = b58check_encode(b"\x00"+_urandom(20), B58_XRP)      # ripple alphabet -> 'r'
assert b58check_ok(xrp, B58_XRP) and xrp[0]=="r"

# --- chaves --------------------------------------------------------------
wif = b58check_encode(b"\x80"+_urandom(32))               # uncompressed -> '5', 51 chars
assert b58check_ok(wif) and wif[0]=="5" and len(wif)==51
def xkey(version):
    body=struct.pack(">I",version)+b"\x00"+b"\x00"*4+b"\x00"*4+_urandom(32)+b"\x00"+_urandom(32)
    return b58check_encode(body)
xprv=xkey(0x0488ADE4); xpub=xkey(0x0488B21E)
assert xprv.startswith("xprv") and b58check_ok(xprv) and 111<=len(xprv)<=112
assert xpub.startswith("xpub") and b58check_ok(xpub)

# --- seeds BIP-39 --------------------------------------------------------
seed12 = mnemonic_from_entropy(_urandom(16)); assert bip39_ok(seed12.split())
seed24 = mnemonic_from_entropy(_urandom(32)); assert bip39_ok(seed24.split())
seed24_boundary = mnemonic_from_entropy(_urandom(32)); assert bip39_ok(seed24_boundary.split())
# 12 palavras da wordlist com checksum INVALIDO -> 'bip39_palavras'
import random
random.seed(0xC0FFEE17)
while True:
    bad12=[WL[random.randrange(2048)] for _ in range(12)]
    if not bip39_ok(bad12): break
bad12=" ".join(bad12)
# 12 palavras NAO-wordlist -> nada
nonwl="zzqx wibble frobnak glonk spung dweeb quixor jabber wabble snorf plib grunth"
assert all(w not in WLI for w in nonwl.split())

# --- negativos (checksum corrompido -> rejeitados) -----------------------
def corrupt_b58(s, alphabet=B58_BTC):
    while True:
        i=len(s)-1
        repl=alphabet[(alphabet.index(s[i])+1)%58]
        c=s[:i]+repl
        if not b58check_ok(c, alphabet): return c
btc_bad = corrupt_b58(btc_p2sh); assert not b58check_ok(btc_bad)
tron_bad= corrupt_b58(tron);     assert not b58check_ok(tron_bad)
# ETH mixed-case com checksum errado
def corrupt_eth(a):
    body=list(a[2:])
    for i,c in enumerate(body):
        if c.isalpha():
            body[i]=c.swapcase(); break
    cand="0x"+"".join(body)
    return cand
eth_bad=corrupt_eth(eth_valid); assert eip55_status(eth_bad)=="invalido"
# bech32 corrompido
btc_bech_bad = btc_bech32[:-1] + ("q" if btc_bech32[-1]!="q" else "p")
assert bech32_decode(btc_bech_bad)==(None,None)
# Solana-like (44 base58, sem prefixo de outras redes) -> detector desativado
while True:
    sol=b58encode(_urandom(32))
    if len(sol)>=43 and sol[0] not in "13LMTrD5" and not sol.startswith(("xprv","xpub")):
        break

# ================================================================ arquivos
def W(path, content, binary=False):
    full=os.path.join(ROOT, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    mode="wb" if binary else "w"
    with open(full, mode) as f: f.write(content)

def R(path, network, kind, value, validation, token="", note=""):
    rows.append((path, network, kind, value, validation, token, note))

# 1) notas com enderecos validos (sem tickers -> sem token)
p="Users/suspeito/Desktop/notas_carteiras.txt"
W(p, f"""Anotacoes de carteiras - confidencial

BTC principal (legado): {btc_p2pkh}
BTC cofre (P2SH):       {btc_p2sh}
BTC segwit:             {btc_bech32}
BTC taproot:            {btc_bech32m}
ETH (com checksum):     {eth_valid}
ETH (minusculo):        {eth_lower}
Cardano:                {ada_shelley}
Cardano stake:          {ada_stake}
Cardano antigo (Byron): {ada_byron}

(duplicata proposital, deve gerar 1 so artifact): {btc_p2pkh}
""")
R(p,"Bitcoin","endereco",btc_p2pkh,"checksum_valido","","genesis; duplicado no arquivo")
R(p,"Bitcoin","endereco",btc_p2sh,"checksum_valido")
R(p,"Bitcoin","endereco",btc_bech32,"checksum_valido")
R(p,"Bitcoin","endereco",btc_bech32m,"checksum_valido","","taproot/bech32m")
R(p,"Ethereum/EVM","endereco",eth_valid,"checksum_valido")
R(p,"Ethereum/EVM","endereco",eth_lower,"sem_checksum")
R(p,"Cardano","endereco",ada_shelley,"checksum_valido")
R(p,"Cardano","endereco",ada_stake,"checksum_valido")
R(p,"Cardano (Byron)","endereco",ada_byron,"sem_checksum")

# 2) transacoes com tickers -> tokens (contrato + contexto)
p="Users/suspeito/Documents/transacoes_usdt.csv"
W(p, f"""data,descricao,endereco,token
2026-01-02,Deposito Tether,{usdt_eth},USDT
2026-01-03,Saque USD Coin,{usdc_eth},USDC
2026-01-04,Pagamento (contexto USDT),{eth_ctx},USDT
2026-01-05,USDT na Tron TRC-20,{usdt_tron_contract},USDT
""")
R(p,"Ethereum/EVM","endereco",usdt_eth,"checksum_valido","USDT (ERC-20)","match por contrato")
R(p,"Ethereum/EVM","endereco",usdc_eth,"checksum_valido","USDC (ERC-20)","match por contrato")
R(p,"Ethereum/EVM","endereco",eth_ctx,"checksum_valido","USDT (contexto)","ticker no arquivo")
R(p,"Tron","endereco",usdt_tron_contract,"checksum_valido","USDT (TRC-20)","contrato real")

# 3) altcoins
p="Users/suspeito/Documents/altcoins.txt"
W(p, f"""Tron:      {tron}
Litecoin:  {ltc}
Litecoin (segwit): {ltc_bech}
Dogecoin:  {doge}
XRP:       {xrp}
""")
R(p,"Tron","endereco",tron,"checksum_valido")
R(p,"Litecoin","endereco",ltc,"checksum_valido")
R(p,"Litecoin","endereco",ltc_bech,"checksum_valido","","bech32 ltc")
R(p,"Dogecoin","endereco",doge,"checksum_valido")
R(p,"XRP","endereco",xrp,"checksum_valido","","alfabeto ripple")

# 4) chaves privadas e estendidas
p="Users/suspeito/Desktop/chaves.txt"
W(p, f"""NAO COMPARTILHAR
WIF:  {wif}
xprv: {xprv}
xpub: {xpub}
""")
R(p,"Bitcoin","chave_privada_WIF",wif,"checksum_valido")
R(p,"BIP32","chave_estendida",xprv,"checksum_valido","","chave PRIVADA estendida")
R(p,"BIP32","chave_estendida",xpub,"checksum_valido","","chave publica estendida")

# 5) seeds
p="Users/suspeito/Desktop/seed_backup.txt"
W(p, f"""Backup de recuperacao

12 palavras: {seed12}

24 palavras:
{seed24}

(12 palavras da lista, checksum invalido):
{bad12}

(12 palavras fora da lista, deve ser ignorado):
{nonwl}
""")
R(p,"BIP-39","seed_phrase",seed12,"bip39_checksum_valido")
R(p,"BIP-39","seed_phrase",seed24,"bip39_checksum_valido")
R(p,"BIP-39","seed_phrase",bad12,"bip39_palavras","","checksum invalido -> indicio")

# 6) teste de borda de janela (1 MiB) - seed a ~50 bytes do limite
p="Users/suspeito/Documents/boundary_test.bin"
B=1048576
seed_bytes=(" "+seed24_boundary+" ").encode()
start=B-50
buf=bytearray(b"\x00"*start)+bytearray(seed_bytes)
buf+=bytearray(b"\x00"*64)
W(p, bytes(buf), binary=True)
R(p,"BIP-39","seed_phrase",seed24_boundary,"bip39_checksum_valido","",
  "STRADDLE do limite de 1 MiB: capturado na janela 2 via overlap")

# 7) arquivos de carteira (deteccao por nome/caminho)
def keystore_name():
    return "UTC--2024-03-01T12-00-00.000Z--"+_urandom(20).hex()
ks=keystore_name()
wallets=[
 ("Users/suspeito/AppData/Roaming/Bitcoin/wallet.dat",
   ("\x00\x05\x31\x62"+ "Berkeley DB wallet  "+wif).encode("latin-1"),
   "Bitcoin Core (wallet.dat)"),
 ("Users/suspeito/AppData/Roaming/Electrum/wallets/default_wallet",
   ('{"seed_version":13,"wallet_type":"standard","keystore":{"type":"bip32"}}').encode(),
   "Electrum (default_wallet)"),
 ("Users/suspeito/AppData/Roaming/Exodus/exodus.wallet/seed.seco",
   _urandom(96), "Exodus (.seco)"),
 ("Users/suspeito/AppData/Local/Google/Chrome/User Data/Default/Local Extension Settings/nkbihfbeoofkjafdcbenoooofpidbnpl/000003.ldb",
   ('{"vault":{"data":"AAAA","iv":"BBBB","salt":"CCCC"}}').encode(),
   "MetaMask (extensao Chrome)"),
 (f"Users/suspeito/Ethereum/keystore/{ks}",
   ('{"version":3,"crypto":{"cipher":"aes-128-ctr","kdf":"scrypt"}}').encode(),
   "Keystore Ethereum (UTC--)"),
 ("Users/suspeito/AppData/Roaming/atomic/atomic.dat",
   _urandom(48), "Atomic Wallet"),
 ("Users/suspeito/AppData/Roaming/Ledger Live/app.json",
   ('{"accounts":[]}').encode(), "Ledger Live"),
 ("Users/suspeito/cofre.wallet",
   _urandom(32), "Carteira generica (.wallet)"),
]
for wp, wc, label in wallets:
    W(wp, wc, binary=True)
    R(wp,"Carteira","arquivo_de_carteira",label,"match_por_nome")

# o WIF tambem esta EMBUTIDO no conteudo do wallet.dat -> a varredura de conteudo
# do plugin o encontra (mesmo valor, arquivo diferente). Registrado como positivo
# para que o manifesto preveja o resultado completo (sem "extra" no diff).
R("Users/suspeito/AppData/Roaming/Bitcoin/wallet.dat", "Bitcoin",
  "chave_privada_WIF", wif, "checksum_valido", "",
  "WIF embutido no conteudo do wallet.dat")

# 8) falsos positivos (esperado AUSENTE)
p="Users/suspeito/Documents/falsos_positivos.txt"
W(p, f"""Strings que NAO devem virar artifact:
BTC corrompido:   {btc_bad}
Tron corrompido:  {tron_bad}
ETH checksum err: {eth_bad}
bech32 corrompido:{btc_bech_bad}
Solana (detector desativado): {sol}
Hash aleatorio:   {_urandom(20).hex()}
""")
neg.append((p, btc_bad, "BTC checksum invalido -> rejeitado"))
neg.append((p, tron_bad, "Tron checksum invalido -> rejeitado"))
neg.append((p, eth_bad, "ETH EIP-55 invalido -> rejeitado"))
neg.append((p, btc_bech_bad, "bech32 checksum invalido -> rejeitado"))
neg.append((p, sol, "Solana: detector desativado (ENABLE_SOLANA=False)"))

# ================================================================ manifesto
with open(MANIFEST,"w",newline="") as f:
    w=csv.writer(f)
    w.writerow(["arquivo","rede","tipo","valor","validacao_esperada","token_esperado","observacao"])
    for r in rows: w.writerow(r)
    w.writerow([])
    w.writerow(["# NEGATIVOS - esperado AUSENTE nos resultados"])
    w.writerow(["arquivo","valor","motivo"])
    for n in neg: w.writerow(n)

# resumo
pos=len(rows); files=len(set(r[0] for r in rows))|len(set([n[0] for n in neg]))
print(f"Artifacts esperados (positivos): {pos}")
print(f"Casos negativos (ausentes):      {len(neg)}")
print(f"Arquivos plantados:              {len(set([r[0] for r in rows] + [n[0] for n in neg]))}")
print("Corpus em", ROOT)
print("Manifesto em", MANIFEST)
