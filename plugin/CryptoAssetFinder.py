# -*- coding: utf-8 -*-
#
# CryptoAssetFinder - Autopsy Data Source Ingest Module (Jython 2.7)
# -----------------------------------------------------------------------------
# Detecta artefatos de criptomoedas em imagens forenses:
#   - Enderecos: BTC (P2PKH/P2SH/Bech32/Bech32m), Ethereum/EVM (EIP-55),
#     Cardano (Shelley/Byron), Tron, Litecoin, Dogecoin, XRP, (Solana opcional)
#   - Chaves: WIF, chaves estendidas (xprv/xpub/...), keystore Ethereum
#   - Seeds: frases BIP-39 (12/15/18/21/24 palavras) com validacao de checksum
#   - Arquivos de carteira: wallet.dat, Electrum, MetaMask, Exodus, Atomic,
#     Ledger Live, Trezor, Coinbase, keystore
#
# Toda a validacao de checksum e feita em Jython puro (base58check, bech32/
# bech32m e BIP-39) ou via BouncyCastle (Keccak-256 para EIP-55), sem
# dependencias externas de terceiros, para maxima auditabilidade pericial.
#
# Classifica USDT/USDC por CONTEXTO (endereco de contrato + ticker), pois sao
# tokens hospedados em outras redes, nao cadeias com formato proprio.
#
# Autor: Blue Vault (esqueleto gerado para customizacao)
# Licenca: use livre. Valide os algoritmos contra vetores de teste oficiais
#          antes de empregar em pericia.
# -----------------------------------------------------------------------------

import jarray
import inspect
import os
import re
import hashlib
import base64

from java.lang import String as JString
from java.util.logging import Level

from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel.BlackboardAttribute import TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE as ATTR_VT
from org.sleuthkit.datamodel import TskData

from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case

# Keccak-256 (Ethereum). BouncyCastle ja vem no ambiente do Autopsy.
# NUNCA usar SHA3-256 da JVM: e a variante NIST, diferente do Keccak original.
try:
    from org.bouncycastle.crypto.digests import KeccakDigest
    HAVE_KECCAK = True
except ImportError:
    HAVE_KECCAK = False

# Blake2b-512 (SS58 / Polkadot) e SHA-512/256 (Algorand), tambem via BouncyCastle.
try:
    from org.bouncycastle.crypto.digests import Blake2bDigest
    HAVE_BLAKE2B = True
except ImportError:
    HAVE_BLAKE2B = False
try:
    from org.bouncycastle.crypto.digests import SHA512tDigest
    HAVE_SHA512T = True
except ImportError:
    HAVE_SHA512T = False

MODULE_NAME = "CryptoAssetFinder"
MODULE_VERSION = "1.0.0"

# Caps de performance (arquivo unico). Acima do cap, ainda checamos o NOME
# do arquivo (deteccao de carteira), mas nao varremos o conteudo.
CONTENT_SCAN_CAP = 250 * 1024 * 1024   # 250 MiB
READ_WINDOW = 1 * 1024 * 1024          # 1 MiB
READ_OVERLAP = 256                     # sobreposicao para nao perder match na borda

# Liga deteccao de Solana (base58 sem prefixo -> MUITO falso-positivo).
# Deixe False salvo necessidade explicita; ligue com consciencia do ruido.
ENABLE_SOLANA = False

# Alfabetos base58
B58_BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_XRP = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

# Charset bech32 (BIP-173)
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# Contratos de stablecoin conhecidos (minusculo p/ EVM). Confirme num explorer.
TOKEN_CONTRACTS = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT (ERC-20)",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC (ERC-20)",
    "tr7nhqjekqxgtci8q8zy4pl8otszgjlj6t":          "USDT (TRC-20)",
}
TOKEN_TICKERS = ["tether", "usdt", "usd coin", "usdc"]

# Padroes de arquivo de carteira (sobre o caminho completo, case-insensitive).
# IMPORTANTE: o primeiro match vence. Coloque padroes ESPECIFICOS (nome/extensao)
# antes dos padroes de DIRETORIO, para que o rotulo mais informativo prevaleca
# (ex.: "Exodus (.seco)" e melhor que so "Exodus (diretorio)").
WALLET_FILE_PATTERNS = [
    ("Bitcoin Core (wallet.dat)",   r'(?:^|[\\/])wallet\.dat$'),
    ("Electrum (default_wallet)",   r'(?:^|[\\/])default_wallet$'),
    ("Keystore Ethereum (UTC--)",   r'UTC--[^\\/]*--[0-9a-fA-F]{40}'),
    ("MetaMask (extensao Chrome)",  r'nkbihfbeoofkjafdcbenoooofpidbnpl'),
    ("Exodus (.seco)",              r'\.seco$'),
    ("Exodus (diretorio)",          r'[\\/][Ee]xodus[\\/]'),
    ("Electrum (diretorio)",        r'[\\/]\.?electrum[\\/]'),
    ("Atomic Wallet",               r'[\\/][Aa]tomic[\\/]'),
    ("Trust Wallet",                r'trustwallet'),
    ("Ledger Live",                 r'[\\/]Ledger\s?Live[\\/]'),
    ("Trezor Suite",                r'[\\/]@?trezor[\\/]'),
    ("Coinbase Wallet",             r'[\\/]Coinbase'),
    ("Carteira generica (.wallet)", r'\.wallet$'),
]


# =============================================================================
# Validadores criptograficos (Jython puro)
# =============================================================================

def b58_decode(s, alphabet=B58_BTC):
    num = 0
    for ch in s:
        idx = alphabet.find(ch)
        if idx < 0:
            raise ValueError("caractere base58 invalido")
        num = num * 58 + idx
    out = bytearray()
    while num > 0:
        out.insert(0, num & 0xff)
        num >>= 8
    pad = 0
    for ch in s:
        if ch == alphabet[0]:
            pad += 1
        else:
            break
    return str(bytearray(pad) + out)


def b58check_ok(s, alphabet=B58_BTC):
    """Valida base58check (checksum = 4 primeiros bytes de SHA256d)."""
    try:
        raw = b58_decode(s, alphabet)
    except ValueError:
        return False
    if len(raw) < 5:
        return False
    payload, checksum = raw[:-4], raw[-4:]
    calc = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return calc == checksum


def _bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_decode(bech):
    """Retorna (hrp, spec) onde spec e 'bech32', 'bech32m' ou None."""
    if any(ord(x) < 33 or ord(x) > 126 for x in bech):
        return (None, None)
    if bech.lower() != bech and bech.upper() != bech:
        return (None, None)   # mistura de caixa nao e permitida em bech32
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech):
        return (None, None)
    if not all(x in BECH32_CHARSET for x in bech[pos + 1:]):
        return (None, None)
    hrp = bech[:pos]
    data = [BECH32_CHARSET.find(x) for x in bech[pos + 1:]]
    const = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if const == 1:
        return (hrp, "bech32")
    if const == 0x2bc830a3:
        return (hrp, "bech32m")
    return (None, None)


def bech32_ok(s, expected_hrps):
    hrp, spec = bech32_decode(s)
    return hrp is not None and hrp in expected_hrps


def keccak256_hex(ascii_str):
    """Keccak-256 (Ethereum) via BouncyCastle. Entrada ascii (endereco hex)."""
    d = KeccakDigest(256)
    jb = JString(ascii_str).getBytes("ISO-8859-1")
    d.update(jb, 0, len(jb))
    out = jarray.zeros(32, 'b')
    d.doFinal(out, 0)
    return ''.join('%02x' % (b & 0xff) for b in out)


def eip55_status(addr):
    """
    addr no formato 0x + 40 hex.
    Retorna 'checksum_valido', 'sem_checksum' ou 'invalido'.
    """
    body = addr[2:]
    if len(body) != 40 or not re.match(r'^[0-9a-fA-F]{40}$', body):
        return "invalido"
    low = body.lower()
    if body == low or body == body.upper():
        return "sem_checksum"   # formato valido, checksum nao presente
    if not HAVE_KECCAK:
        return "sem_checksum"   # nao temos como verificar; nao rejeitamos
    h = keccak256_hex(low)
    out = []
    for i, ch in enumerate(low):
        if ch in "0123456789":
            out.append(ch)
        else:
            out.append(ch.upper() if int(h[i], 16) >= 8 else ch)
    return "checksum_valido" if ("0x" + "".join(out)) == addr else "invalido"


def bip39_checksum_ok(words, index):
    """Valida o checksum BIP-39 de uma sequencia de palavras."""
    n = len(words)
    if n not in (12, 15, 18, 21, 24):
        return False
    idxs = []
    for w in words:
        if w not in index:
            return False
        idxs.append(index[w])
    bits = ''.join(format(i, '011b') for i in idxs)
    total = n * 11
    cs_len = total // 33
    ent_len = total - cs_len
    ent_bits, cs_bits = bits[:ent_len], bits[ent_len:]
    ent = bytearray()
    for i in range(0, ent_len, 8):
        ent.append(int(ent_bits[i:i + 8], 2))
    h = hashlib.sha256(str(ent)).digest()
    hbits = ''.join(format(ord(c), '08b') for c in h)
    return hbits[:cs_len] == cs_bits


# =============================================================================
# Validadores adicionais (8 moedas com checksum proprio)
# Algoritmos aferidos contra enderecos reais conhecidos e libs de referencia.
# =============================================================================

B32_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
MONERO_ENC_TO_DEC = {0: 0, 2: 1, 3: 2, 5: 3, 6: 4, 7: 5, 9: 6, 10: 7, 11: 8}
CASHADDR_GEN = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470]
COSMOS_HRPS = set([
    "cosmos", "osmo", "inj", "celestia", "akash", "juno", "secret", "stars",
    "axelar", "kava", "evmos", "dydx", "neutron", "stride", "regen", "band",
    "sei", "persistence", "kujira", "agoric", "umee", "stargaze"])

# --- bytes <-> java byte[] e digests via BouncyCastle ---
def _jbytes(data):
    ba = bytearray(data)
    arr = jarray.zeros(len(ba), 'b')
    for i in range(len(ba)):
        v = ba[i]
        arr[i] = v if v < 128 else v - 256
    return arr

def keccak256_bytes(data):
    d = KeccakDigest(256)
    jb = _jbytes(data)
    d.update(jb, 0, len(jb))
    out = jarray.zeros(32, 'b')
    d.doFinal(out, 0)
    return bytearray((b & 0xff) for b in out)

def blake2b512_bytes(data):
    d = Blake2bDigest(512)
    jb = _jbytes(data)
    d.update(jb, 0, len(jb))
    out = jarray.zeros(64, 'b')
    d.doFinal(out, 0)
    return bytearray((b & 0xff) for b in out)

def sha512_256_bytes(data):
    d = SHA512tDigest(256)
    jb = _jbytes(data)
    d.update(jb, 0, len(jb))
    out = jarray.zeros(32, 'b')
    d.doFinal(out, 0)
    return bytearray((b & 0xff) for b in out)

# --- decoders ---
def base32_decode(s):
    bits = 0; val = 0; out = bytearray()
    for c in s:
        i = B32_CHARSET.find(c)
        if i < 0:
            raise ValueError("base32 invalido")
        val = (val << 5) | i; bits += 5
        if bits >= 8:
            bits -= 8; out.append((val >> bits) & 0xff)
    return out

def _mn_block(block, size):
    num = 0
    for ch in block:
        idx = B58_BTC.find(ch)
        if idx < 0:
            raise ValueError("char monero invalido")
        num = num * 58 + idx
    if num >= (1 << (8 * size)):
        raise ValueError("overflow monero")
    b = bytearray(size)
    for i in range(size - 1, -1, -1):
        b[i] = num & 0xff; num >>= 8
    return b

def monero_b58_decode(s):
    out = bytearray(); full = len(s) // 11; rem = len(s) % 11
    for i in range(full):
        out += _mn_block(s[i * 11:i * 11 + 11], 8)
    if rem:
        size = MONERO_ENC_TO_DEC.get(rem, 0)
        if size == 0:
            raise ValueError("bloco monero invalido")
        out += _mn_block(s[full * 11:], size)
    return out

def crc16_xmodem(data):
    crc = 0
    for byte in bytearray(data):
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xffff
            else:
                crc = (crc << 1) & 0xffff
    return crc

def _b64_ton(s):
    s2 = s.replace('-', '+').replace('_', '/')
    pad = (-len(s2)) % 4
    return bytearray(base64.b64decode(s2 + '=' * pad))

def _cashaddr_polymod(values):
    c = 1
    for d in values:
        c0 = c >> 35
        c = ((c & 0x07ffffffff) << 5) ^ d
        for i in range(5):
            if (c0 >> i) & 1:
                c ^= CASHADDR_GEN[i]
    return c ^ 1

# --- validadores ---
def monero_ok(s):
    if len(s) not in (95, 106) or not HAVE_KECCAK:
        return False
    try:
        raw = monero_b58_decode(s)
    except ValueError:
        return False
    if len(raw) < 5:
        return False
    if keccak256_bytes(raw[:-4])[:4] != raw[-4:]:
        return False
    return raw[0] in (18, 19, 42)   # mainnet padrao/integrado/subaddress

def stellar_ok(s):
    if len(s) != 56:
        return False
    try:
        raw = base32_decode(s)
    except ValueError:
        return False
    if len(raw) != 35:
        return False
    if crc16_xmodem(raw[:-2]) != (raw[-2] | (raw[-1] << 8)):   # little-endian
        return False
    return raw[0] in (0x30, 0x90)   # 0x30=G publica, 0x90=S secreta

def ton_ok(s):
    if len(s) != 48:
        return False
    try:
        raw = _b64_ton(s)
    except Exception:
        return False
    if len(raw) != 36:
        return False
    return crc16_xmodem(raw[:34]) == ((raw[34] << 8) | raw[35])   # big-endian

def ss58_ok(s):
    if not (46 <= len(s) <= 48) or not HAVE_BLAKE2B:
        return False
    try:
        raw = bytearray(b58_decode(s))
    except ValueError:
        return False
    if len(raw) != 35:
        return False
    h = blake2b512_bytes(b"SS58PRE" + bytes(raw[:33]))
    return h[0] == raw[33] and h[1] == raw[34]

def algorand_ok(s):
    if len(s) != 58 or not HAVE_SHA512T:
        return False
    try:
        raw = base32_decode(s)
    except ValueError:
        return False
    if len(raw) != 36:
        return False
    return sha512_256_bytes(raw[:32])[-4:] == raw[32:36]

def tezos_ok(s):
    if s[:3] not in ("tz1", "tz2", "tz3", "KT1"):
        return False
    return b58check_ok(s)

def cosmos_ok(s):
    hrp, spec = bech32_decode(s)
    if not hrp:
        return False
    for suf in ("valoperpub", "valconspub", "valoper", "valcons", "pub"):
        if hrp.endswith(suf):
            hrp = hrp[:-len(suf)]
            break
    return hrp in COSMOS_HRPS

def cashaddr_ok(s):
    if ":" in s:
        prefix, payload = s.split(":", 1)
    else:
        prefix, payload = "bitcoincash", s
    prefix = prefix.lower(); payload = payload.lower()
    for c in payload:
        if c not in BECH32_CHARSET:
            return False
    data = [BECH32_CHARSET.find(c) for c in payload]
    pe = [ord(c) & 0x1f for c in prefix] + [0]
    return _cashaddr_polymod(pe + data) == 0


# =============================================================================
# Factory
# =============================================================================

class CryptoAssetFinderFactory(IngestModuleFactoryAdapter):

    def getModuleDisplayName(self):
        return "Crypto Asset Finder"

    def getModuleDescription(self):
        return ("Detecta enderecos, chaves, seeds BIP-39 e arquivos de carteira "
                "de criptomoedas, com validacao de checksum. Marca achados como "
                "itens de interesse.")

    def getModuleVersionNumber(self):
        return MODULE_VERSION

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return CryptoAssetFinderModule()


# =============================================================================
# Modulo de ingestao
# =============================================================================

class CryptoAssetFinderModule(DataSourceIngestModule):

    _logger = Logger.getLogger(MODULE_NAME)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__,
                          inspect.stack()[1][3], msg)

    def startUp(self, context):
        self.context = context

        skCase = Case.getCurrentCase().getSleuthkitCase()
        self.blackboard = skCase.getBlackboard()

        # Tipo de artifact customizado e seus atributos
        self.artType = self.blackboard.getOrAddArtifactType(
            "TSK_CRYPTO_ASSET", "Ativo Cripto")
        self.attValue = self.blackboard.getOrAddAttributeType(
            "TSK_CRYPTO_VALUE", ATTR_VT.STRING, "Endereco/Valor")
        self.attNet = self.blackboard.getOrAddAttributeType(
            "TSK_CRYPTO_NETWORK", ATTR_VT.STRING, "Rede")
        self.attKind = self.blackboard.getOrAddAttributeType(
            "TSK_CRYPTO_KIND", ATTR_VT.STRING, "Tipo de artefato")
        self.attValid = self.blackboard.getOrAddAttributeType(
            "TSK_CRYPTO_VALIDATION", ATTR_VT.STRING, "Validacao")
        self.attToken = self.blackboard.getOrAddAttributeType(
            "TSK_CRYPTO_TOKEN", ATTR_VT.STRING, "Token classificado")
        self.attOffset = self.blackboard.getOrAddAttributeType(
            "TSK_CRYPTO_OFFSET", ATTR_VT.LONG, "Offset no arquivo")

        # BIP-39 (multi-idioma: carrega todas as wordlists presentes)
        self.bip39 = self._load_wordlists()

        # Compila detectores de regex
        self._build_detectors()

        self.found_total = 0

    # --- carregamento das wordlists BIP-39 -----------------------------------
    def _module_dir(self):
        return os.path.dirname(os.path.abspath(
            inspect.getsourcefile(lambda: 0)))

    # Wordlists BIP-39 reconhecidas (arquivo oficial -> codigo de idioma).
    # Todas as oficiais sao ASCII (inclusive a portuguesa, sem acentos), entao
    # o tokenizer [a-z]+ e a leitura latin-1 servem para todas. As listas em
    # japones/coreano/chines NAO entram aqui: usam script nao-latino e
    # separador ideografico, exigindo tokenizacao propria.
    WORDLIST_FILES = [
        ("english.txt",    "en"),
        ("portuguese.txt", "pt"),
        ("spanish.txt",    "es"),
        ("french.txt",     "fr"),
        ("italian.txt",    "it"),
        ("czech.txt",      "cs"),
    ]

    def _load_wordlists(self):
        wls = {}
        for fname, lang in self.WORDLIST_FILES:
            path = os.path.join(self._module_dir(), fname)
            if not os.path.exists(path):
                continue
            index = {}
            i = 0
            fh = open(path, "r")
            try:
                for line in fh:
                    w = line.strip()
                    if w:
                        index[w] = i
                        i += 1
            finally:
                fh.close()
            if len(index) != 2048:
                self.log(Level.WARNING,
                         "Wordlist %s com %d palavras (esperado 2048)" % (fname, len(index)))
            wls[lang] = index
        if not wls:
            self.log(Level.WARNING,
                     "Nenhuma wordlist BIP-39 encontrada; deteccao de seed desativada")
        else:
            self.log(Level.INFO,
                     "Wordlists BIP-39 carregadas: " + ", ".join(sorted(wls.keys())))
        return wls

    # --- registro de detectores ----------------------------------------------
    def _build_detectors(self):
        # Cada item: (rede, tipo, regex_compilado, validador, validacao_quando_ok)
        # validador recebe a string e retorna True/False ou um status string.
        nb = r'(?<![1-9A-HJ-NP-Za-km-z])'   # boundary base58 (antes)
        na = r'(?![1-9A-HJ-NP-Za-km-z])'    # boundary base58 (depois)
        self.detectors = []

        # Bitcoin P2PKH/P2SH
        self.detectors.append((
            "Bitcoin", "endereco",
            re.compile(nb + r'[13][1-9A-HJ-NP-Za-km-z]{25,34}' + na),
            lambda s: "checksum_valido" if b58check_ok(s) else None, None))

        # Bitcoin Bech32 / Bech32m (SegWit / Taproot)
        self.detectors.append((
            "Bitcoin", "endereco",
            re.compile(r'(?<![a-z0-9])bc1[a-z0-9]{8,87}'),
            lambda s: "checksum_valido" if bech32_ok(s, ["bc"]) else None, None))

        # Ethereum / EVM (cobre USDT/USDC ERC-20, classificados depois)
        self.detectors.append((
            "Ethereum/EVM", "endereco",
            re.compile(r'(?<![0-9a-fA-Fx])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])'),
            self._eth_validator, None))

        # Cardano Shelley (bech32)
        self.detectors.append((
            "Cardano", "endereco",
            re.compile(r'(?<![a-z0-9])(?:addr1|stake1)[a-z0-9]{50,110}'),
            lambda s: "checksum_valido" if bech32_ok(s, ["addr", "stake"]) else None,
            None))

        # Cardano Byron (base58, sem base58check classico -> sem_checksum)
        self.detectors.append((
            "Cardano (Byron)", "endereco",
            re.compile(nb + r'(?:Ddz|Ae2)[1-9A-HJ-NP-Za-km-z]{50,110}' + na),
            lambda s: "sem_checksum", None))

        # Tron (USDT-TRC20 vive aqui)
        self.detectors.append((
            "Tron", "endereco",
            re.compile(nb + r'T[1-9A-HJ-NP-Za-km-z]{33}' + na),
            lambda s: "checksum_valido" if b58check_ok(s) else None, None))

        # Litecoin base58 (L/M)
        self.detectors.append((
            "Litecoin", "endereco",
            re.compile(nb + r'[LM][1-9A-HJ-NP-Za-km-z]{25,34}' + na),
            lambda s: "checksum_valido" if b58check_ok(s) else None, None))

        # Litecoin bech32
        self.detectors.append((
            "Litecoin", "endereco",
            re.compile(r'(?<![a-z0-9])ltc1[a-z0-9]{8,87}'),
            lambda s: "checksum_valido" if bech32_ok(s, ["ltc"]) else None, None))

        # Dogecoin
        self.detectors.append((
            "Dogecoin", "endereco",
            re.compile(nb + r'D[1-9A-HJ-NP-Za-km-z]{33}' + na),
            lambda s: "checksum_valido" if b58check_ok(s) else None, None))

        # XRP (alfabeto base58 proprio do Ripple)
        self.detectors.append((
            "XRP", "endereco",
            re.compile(nb + r'r[1-9A-HJ-NP-Za-km-z]{24,34}' + na),
            lambda s: "checksum_valido" if b58check_ok(s, B58_XRP) else None, None))

        # ---- moedas adicionais (checksum proprio, validado) ----

        # Monero (privacy coin - prioridade forense)
        self.detectors.append((
            "Monero", "endereco",
            re.compile(nb + r'[48][1-9A-HJ-NP-Za-km-z]{94,105}' + na),
            lambda s: "checksum_valido" if monero_ok(s) else None, None))

        # Cosmos e ecossistema (bech32 com hrp de cadeia)
        cosmos_re = r'(?<![a-z0-9])(?:%s)(?:valoperpub|valconspub|valoper|valcons|pub)?1[ac-hj-np-z02-9]{38,70}' % "|".join(sorted(COSMOS_HRPS))
        self.detectors.append((
            "Cosmos", "endereco",
            re.compile(cosmos_re),
            lambda s: "checksum_valido" if cosmos_ok(s) else None, None))

        # Stellar - chave publica (G)
        self.detectors.append((
            "Stellar", "endereco",
            re.compile(r'(?<![A-Z2-7])G[A-Z2-7]{55}(?![A-Z2-7])'),
            lambda s: "checksum_valido" if stellar_ok(s) else None, None))

        # Stellar - chave SECRETA (S) -- altissimo valor probatorio
        self.detectors.append((
            "Stellar", "chave_secreta",
            re.compile(r'(?<![A-Z2-7])S[A-Z2-7]{55}(?![A-Z2-7])'),
            lambda s: "checksum_valido" if stellar_ok(s) else None, None))

        # TON (Toncoin) - base64url + CRC16
        self.detectors.append((
            "TON", "endereco",
            re.compile(r'(?<![A-Za-z0-9_/+\-])[EUk0][A-Za-z0-9_/+\-]{47}(?![A-Za-z0-9_/+\-])'),
            lambda s: "checksum_valido" if ton_ok(s) else None, None))

        # Polkadot / Kusama / Substrate (SS58 + Blake2b)
        self.detectors.append((
            "Polkadot/Substrate (SS58)", "endereco",
            re.compile(nb + r'[1-9A-HJ-NP-Za-km-z]{46,48}' + na),
            lambda s: "checksum_valido" if ss58_ok(s) else None, None))

        # Algorand (base32 + SHA-512/256)
        self.detectors.append((
            "Algorand", "endereco",
            re.compile(r'(?<![A-Z2-7])[A-Z2-7]{58}(?![A-Z2-7])'),
            lambda s: "checksum_valido" if algorand_ok(s) else None, None))

        # Tezos (base58check tz1/tz2/tz3/KT1)
        self.detectors.append((
            "Tezos", "endereco",
            re.compile(nb + r'(?:tz1|tz2|tz3|KT1)[1-9A-HJ-NP-Za-km-z]{33}' + na),
            lambda s: "checksum_valido" if tezos_ok(s) else None, None))

        # Bitcoin Cash - CashAddr (o legado base58 1.../3... casa no detector BTC)
        self.detectors.append((
            "Bitcoin Cash", "endereco",
            re.compile(r'(?<![A-Za-z0-9:])(?:bitcoincash:|bchtest:)?[qp][a-z0-9]{41}(?![a-z0-9])'),
            lambda s: "checksum_valido" if cashaddr_ok(s) else None, None))

        # WIF (chave privada Bitcoin) - ALTO valor probatorio
        self.detectors.append((
            "Bitcoin", "chave_privada_WIF",
            re.compile(nb + r'[5KL][1-9A-HJ-NP-Za-km-z]{50,51}' + na),
            lambda s: "checksum_valido" if b58check_ok(s) else None, None))

        # Chaves estendidas (xprv = ALTISSIMO valor; xpub etc.)
        self.detectors.append((
            "BIP32", "chave_estendida",
            re.compile(nb + r'(?:xprv|xpub|yprv|ypub|zprv|zpub|Ltpv|Ltub)'
                       r'[1-9A-HJ-NP-Za-km-z]{107,108}' + na),
            lambda s: "checksum_valido" if b58check_ok(s) else None, None))

        # Solana (opcional - base58 sem prefixo, muito falso-positivo)
        if ENABLE_SOLANA:
            self.detectors.append((
                "Solana", "endereco",
                re.compile(nb + r'[1-9A-HJ-NP-Za-km-z]{32,44}' + na),
                lambda s: "sem_checksum", None))

    def _eth_validator(self, s):
        st = eip55_status(s)
        return st if st in ("checksum_valido", "sem_checksum") else None

    # --- leitura de conteudo em janelas --------------------------------------
    def _iter_windows(self, f):
        size = f.getSize()
        if size == 0 or size > CONTENT_SCAN_CAP:
            return
        buf = jarray.zeros(READ_WINDOW, 'b')
        offset = 0
        step = READ_WINDOW - READ_OVERLAP
        while offset < size:
            to_read = min(READ_WINDOW, size - offset)
            n = f.read(buf, offset, to_read)
            if n <= 0:
                break
            # ISO-8859-1 mapeia byte->codepoint 1:1, preservando offsets ascii
            text = unicode(JString(buf, 0, n, "ISO-8859-1"))
            yield offset, text
            if n < READ_WINDOW:
                break
            offset += step

    # --- classificacao de token ----------------------------------------------
    def _classify_token(self, value, window_text_lower):
        v = value.lower()
        if v in TOKEN_CONTRACTS:
            return TOKEN_CONTRACTS[v]
        for t in TOKEN_TICKERS:
            if t in window_text_lower:
                if "usdc" in t or "coin" in t:
                    return "USDC (contexto)"
                return "USDT (contexto)"
        return None

    # --- deteccao de seeds BIP-39 (multi-idioma) -----------------------------
    def _scan_bip39(self, text_lower):
        if not self.bip39:
            return []
        # Tokenizacao e independente de idioma (todas as wordlists oficiais
        # latinas sao ASCII). Escaneia uma vez e testa contra cada idioma.
        tokens = re.findall(r'[a-z]+', text_lower)
        results = []
        for lang, index in self.bip39.items():
            run = []
            for tok in tokens:
                if tok in index:
                    run.append(tok)
                else:
                    results.extend(self._emit_runs(run, index, lang))
                    run = []
            results.extend(self._emit_runs(run, index, lang))
        return results

    def _emit_runs(self, run, index, lang):
        out = []
        for length in (24, 21, 18, 15, 12):
            if len(run) >= length:
                # tenta a janela final de 'length' palavras
                cand = run[len(run) - length:]
                if bip39_checksum_ok(cand, index):
                    out.append((" ".join(cand), "bip39_checksum_valido", lang))
                    return out
        # sem checksum valido, mas >=12 palavras BIP-39 seguidas = indicio
        if len(run) >= 12:
            out.append((" ".join(run[:24]), "bip39_palavras", lang))
        return out

    # --- deteccao de arquivo de carteira -------------------------------------
    def _wallet_file_hit(self, path):
        for label, pat in WALLET_FILE_PATTERNS:
            if re.search(pat, path):
                return label
        return None

    # --- postagem ------------------------------------------------------------
    def _post_asset(self, f, network, kind, value, validation, token, offset):
        try:
            art = f.newArtifact(self.artType.getTypeID())
            attrs = [
                BlackboardAttribute(self.attValue, MODULE_NAME, value),
                BlackboardAttribute(self.attNet, MODULE_NAME, network),
                BlackboardAttribute(self.attKind, MODULE_NAME, kind),
                BlackboardAttribute(self.attValid, MODULE_NAME, validation),
                BlackboardAttribute(self.attOffset, MODULE_NAME, long(offset)),
            ]
            if token:
                attrs.append(BlackboardAttribute(self.attToken, MODULE_NAME, token))
            art.addAttributes(attrs)
            self.blackboard.postArtifact(art, MODULE_NAME)
        except Exception as e:
            self.log(Level.SEVERE, "Falha ao postar artifact: " + str(e))

    def _flag_interesting(self, f, comment):
        try:
            try:
                art = f.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_ITEM)
            except Exception:
                art = f.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            art.addAttribute(BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                MODULE_NAME, "Crypto Assets"))
            art.addAttribute(BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT,
                MODULE_NAME, comment))
            self.blackboard.postArtifact(art, MODULE_NAME)
        except Exception as e:
            self.log(Level.WARNING, "Falha ao marcar interesse: " + str(e))

    # --- varredura de um arquivo ---------------------------------------------
    def _scan_file(self, f):
        findings = []   # (network, kind, value, validation, token, offset)
        seen = set()    # dedup (network, value) dentro do arquivo

        for win_off, text in self._iter_windows(f):
            tlow = text.lower()

            # enderecos / chaves
            for network, kind, rx, validate, _ in self.detectors:
                for m in rx.finditer(text):
                    value = m.group(0)
                    status = validate(value)
                    if not status:        # None/False => invalido, descarta
                        continue
                    key = (network, value)
                    if key in seen:
                        continue
                    seen.add(key)
                    token = None
                    if network in ("Ethereum/EVM", "Tron"):
                        token = self._classify_token(value, tlow)
                    abs_off = win_off + m.start()
                    findings.append((network, kind, value, status, token, abs_off))

            # seeds BIP-39 (com idioma)
            for seed_value, seed_status, seed_lang in self._scan_bip39(tlow):
                key = ("BIP39", seed_lang, seed_value)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(("BIP-39 (%s)" % seed_lang, "seed_phrase",
                                 seed_value, seed_status, None, win_off))

        return findings

    # --- loop principal -------------------------------------------------------
    def process(self, dataSource, progressBar):
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%")
        total = len(files)
        progressBar.switchToDeterminate(total)

        processed = 0
        for f in files:
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK
            processed += 1
            progressBar.progress(processed)

            # Apenas arquivos reais e ALOCADOS (decisao de escopo)
            if not f.isFile():
                continue
            # Excluir slack space: o TSK expoe o residuo de cada arquivo como
            # um arquivo proprio (nome "<arquivo>-slack") de tipo SLACK, que
            # NAO carrega flag "Unalloc". Sem este filtro, padroes de carteira
            # baseados em diretorio/caminho casariam tambem no companheiro slack.
            try:
                if f.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.SLACK:
                    continue
            except Exception:
                pass
            try:
                if "Unalloc" in f.getMetaFlagsAsString():
                    continue
            except Exception:
                pass

            file_findings = []

            # 1) Deteccao por nome/caminho (arquivo de carteira)
            try:
                path = f.getUniquePath()
            except Exception:
                path = (f.getParentPath() or "") + f.getName()
            wallet_label = self._wallet_file_hit(path)
            if wallet_label:
                self._post_asset(f, "Carteira", "arquivo_de_carteira",
                                 wallet_label, "match_por_nome", None, 0)
                file_findings.append("arquivo de carteira: " + wallet_label)

            # 2) Varredura de conteudo
            for (network, kind, value, validation, token, offset) in self._scan_file(f):
                self._post_asset(f, network, kind, value, validation, token, offset)
                label = "%s %s [%s]" % (network, kind, validation)
                if token:
                    label += " (%s)" % token
                file_findings.append(label)

            # 3) Marca o arquivo como interessante (uma vez, com resumo)
            if file_findings:
                self.found_total += len(file_findings)
                summary = "; ".join(file_findings[:8])
                if len(file_findings) > 8:
                    summary += " ... (+%d)" % (len(file_findings) - 8)
                self._flag_interesting(f, summary)

        # Mensagem final na caixa de ingestao
        msg = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, MODULE_NAME,
            "Concluido: %d achados de cripto." % self.found_total)
        IngestServices.getInstance().postMessage(msg)

        return IngestModule.ProcessResult.OK
