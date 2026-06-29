# CryptoAssetFinder — módulo Autopsy (Jython)

Detecta artefatos de criptomoedas em imagens forenses, valida checksums e
marca os achados como itens de interesse, gerando relatório CSV/HTML.

## Estrutura do repositório

```
.
├── plugin/                     # o que se instala no Autopsy
│   ├── CryptoAssetFinder.py    # Data Source Ingest Module (varredura + validação)
│   ├── CryptoAssetReport.py    # General Report Module (consolidação CSV/HTML)
│   ├── english.txt             # wordlist BIP-39 (en) — incluída
│   └── portuguese.txt          # wordlist BIP-39 (pt) — incluída
├── tests/                      # banco de validação e corpus de ground-truth
│   ├── gen_corpus.py           # gera a árvore de evidências + manifesto (determinístico)
│   ├── build_image.sh          # reconstrói a imagem .dd (MBR + ext4) a partir do gerador
│   ├── diff_results.py         # compara export do Autopsy × manifesto esperado
│   ├── validate_new_coins.py   # afere os validadores das moedas vs libs de referência
│   ├── expected_results.csv    # manifesto ground-truth (34 positivos + 5 negativos)
│   └── TESTING.md              # guia de teste ponta a ponta
├── README.md
└── LICENSE
```

A imagem de teste (`tests/crypto_test_image.dd`, ~49 MB) **não é versionada** — é
reconstruída deterministicamente com `tests/build_image.sh` (precisa de
`e2fsprogs`/`mke2fs` e `pycryptodome`; não requer root).

## Instalação

1. Abra o Autopsy e clique no menu **Tools → Python Plugins**. O Autopsy
   abre automaticamente, no gerenciador de arquivos do sistema, a pasta onde
   os módulos Python devem ficar. Não digite o caminho à mão — use sempre
   esse menu, porque o local varia por sistema operacional, versão e perfil
   de usuário. Caminhos típicos:
   - **Windows:** `C:\Users\<usuário>\AppData\Roaming\autopsy\python_modules`
     (a pasta `AppData` é oculta; o menu evita ter de exibi-la manualmente)
   - **Linux:** `~/.autopsy/dev/python_modules` (ou `~/autopsy/python_modules`)
   - **macOS:** `~/Library/Application Support/autopsy/python_modules`

   Se o menu **Python Plugins** não abrir nada (ambiente sem GUI de arquivos),
   crie/localize a pasta `python_modules` manualmente no caminho acima.
2. Dentro de `python_modules`, crie a subpasta `CryptoAssetFinder` e copie para
   dentro dela **todo o conteúdo da pasta `plugin/`** deste repositório (os dois
   `.py` e as wordlists `.txt`). **Cada módulo Python do Autopsy fica em sua
   própria pasta** — isso evita colisão de nomes entre módulos, então não solte
   os `.py` soltos em `python_modules`.
3. As wordlists `english.txt` e `portuguese.txt` **já vêm no repositório** (em
   `plugin/`); ao copiar a pasta inteira, a detecção de seed já funciona. Para
   outros idiomas, adicione os arquivos opcionais na mesma pasta (ver abaixo).
4. Reinicie o Autopsy.

O ingest aparece na lista de módulos ao adicionar/reexecutar uma data source.
O relatório aparece em **Tools → Generate Report → Crypto Asset Report**.

## Wordlists BIP-39 (obrigatórias para detecção de seed)

Por integridade da cadeia de custódia, o módulo carrega as wordlists oficiais
**da própria pasta do plugin** (não as embute no código). O repositório já
inclui `english.txt` e `portuguese.txt`; você pode adicionar outros idiomas.
Sem nenhuma wordlist, a detecção de seed é silenciosamente desativada
(endereços e chaves continuam funcionando).

O módulo é **multi-idioma**: carrega todas as wordlists presentes e marca cada
seed com o idioma detectado (a rede sai como `BIP-39 (en)`, `BIP-39 (pt)`, etc.).
Arquivos reconhecidos (do repositório `bitcoin/bips`, pasta `bip-0039/`):

| Arquivo | Idioma | SHA-256 |
|---|---|---|
| `english.txt` | en | `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` |
| `portuguese.txt` | pt | `2685e9c194c82ae67e10ba59d9ea5345a23dc093e92276fc5361f6667d79cd3f` |
| `spanish.txt` | es | (carregado se presente) |
| `french.txt` | fr | (carregado se presente) |
| `italian.txt` | it | (carregado se presente) |
| `czech.txt` | cs | (carregado se presente) |

- Para perícias no Brasil, recomenda-se ter **english.txt e portuguese.txt**.
  Mas note: a maioria das carteiras gera a seed em **inglês por padrão**,
  mesmo com a interface em português — o `en` é o detector primário; o `pt`
  cobre carteiras que permitem escolher a wordlist em português.
- Todas as wordlists latinas oficiais (inclusive a portuguesa) são **ASCII sem
  acentos**, então o tokenizer e a leitura latin-1 do módulo as suportam sem
  ajuste. As listas em japonês/coreano/chinês **não** são suportadas (script
  não-latino, separador ideográfico — exigiriam tokenização própria).
- **Registre o SHA-256 das wordlists** usadas e cite no laudo: a posição de
  cada palavra na lista entra no cálculo do checksum, então a aferição
  comprova que você usou as listas oficiais, não adulteradas.

## Dependências

Nenhuma de terceiros. A validação é Jython puro, exceto alguns digests que usam
o **BouncyCastle** já presente no Autopsy: **Keccak-256** (EIP-55, Monero),
**Blake2b-512** (SS58/Polkadot) e **SHA-512/256** (Algorand). Se o BouncyCastle
não estiver disponível, os detectores que dependem dele se autodesativam (o
endereço é marcado `sem_checksum` ou simplesmente não casa) — **nunca** se gera
falso-positivo por falta da biblioteca.

## O que é detectado

| Camada | Cobertura | Validação |
|---|---|---|
| Endereços (núcleo) | BTC (P2PKH/P2SH/Bech32/Bech32m), ETH/EVM, Cardano (Shelley/Byron), Tron, Litecoin, Dogecoin, XRP | base58check / bech32 / EIP-55 |
| Endereços (adicionais) | Monero, Cosmos (+ecossistema), Stellar (G e chave secreta S), TON, Polkadot/Kusama/Substrate (SS58), Algorand, Tezos (tz1/tz2/tz3/KT1), Bitcoin Cash (CashAddr) | Keccak / bech32 / CRC16-XMODEM / Blake2b-512 / SHA-512-256 / base58check / CashAddr polymod |
| Chaves | WIF, estendidas (xprv/xpub/…) | base58check |
| Seeds | BIP-39 (12/15/18/21/24 palavras), multi-idioma | checksum BIP-39 |
| Carteiras | wallet.dat, Electrum, MetaMask, Exodus, Atomic, Ledger Live, Trezor, Coinbase, keystore | match por nome/caminho |

USDT/USDC são classificados por **contexto** (contrato + ticker), não por
formato — são tokens, não redes próprias.

**Notas das moedas adicionais:** todos os 8 validadores foram aferidos contra
endereços reais conhecidos (doação Monero, conta Alice SS58, exemplo da spec
CashAddr, burn Tezos) e bibliotecas de referência (`stellar-sdk`, `algosdk`,
`bech32`). Monero, SS58 e Algorand dependem de digests do BouncyCastle
(Keccak/Blake2b/SHA-512-256); se a lib não estiver presente no ambiente do
Autopsy, esses três se autodesativam (retornam sem match) em vez de gerar
falso-positivo. O Bitcoin Cash legado (1.../3...) é, por construção, idêntico
ao Bitcoin e aparece rotulado como **Bitcoin** — apenas o CashAddr
(`bitcoincash:q...`) é rotulado como Bitcoin Cash.

## Status de validação (campo `Validacao`)

- `checksum_valido` / `bip39_checksum_valido` → **prova forte** (checksum confere)
- `match_por_nome` → arquivo de carteira identificado por nome/caminho
- `sem_checksum` → formato válido, checksum não presente/não verificável (ETH
  todo-minúsculo, Cardano Byron) → **indício**, exige corroboração
- `bip39_palavras` → ≥12 palavras BIP-39 seguidas sem checksum válido → indício

## Parâmetros ajustáveis (topo do `CryptoAssetFinder.py`)

- `ENABLE_SOLANA` (padrão `False`) — Solana é base58 sem prefixo e gera muito
  falso-positivo. Ligue só com consciência do ruído.
- `CONTENT_SCAN_CAP` — tamanho máx. por arquivo para varredura de conteúdo.
- `TOKEN_CONTRACTS` — endereços de contrato de stablecoins (confirme num explorer).
- `WALLET_FILE_PATTERNS` — adicione carteiras conforme seus casos.

## Ressalvas periciais (importante para o laudo)

1. **Valide os algoritmos contra vetores de teste oficiais** (endereços
   conhecidos de BTC/ETH/Cardano, seeds BIP-39 de exemplo) antes de empregar.
   O esqueleto está correto por construção, mas a validação independente é
   parte da boa prática pericial.
2. **Escopo:** este módulo varre apenas **arquivos alocados** (decisão de
   projeto). Não cobre unallocated/slack/carving.
3. **Limite de janela:** seeds muito longas que cruzem a borda de uma janela
   de leitura de 1 MiB podem, em teoria, ser perdidas; a sobreposição mitiga,
   mas não elimina, esse caso raro.
4. **Falsos positivos residuais:** mesmo com checksum, um endereço encontrado
   não prova posse/uso — apenas presença na mídia. Trate como ponto de partida
   para correlação (carteiras, históricos de navegador, transações).
5. **Registre versão do módulo e hash da wordlist** no laudo.

## Testes (ground-truth ponta a ponta)

O diretório `tests/` traz um corpus forense **auto-validado e determinístico**:

```bash
cd tests
python3 -m pip install pycryptodome            # gerador usa Keccak
bash build_image.sh                            # gera corpus + manifesto + imagem .dd
#   -> escreve crypto_test_image.dd e expected_results.csv (34 positivos, 5 negativos)
```

Depois, no Autopsy: adicione `crypto_test_image.dd` como data source, rode o
ingest CryptoAssetFinder, gere o Crypto Asset Report (CSV) e compare:

```bash
python3 diff_results.py <export_do_autopsy.csv>   # casa por valor; espera 34/34
```

Para conferir os validadores das moedas isoladamente contra bibliotecas de
referência (requer `pip install stellar-sdk py-algorand-sdk bech32 pycryptodome`):

```bash
python3 validate_new_coins.py
```

O gerador é **determinístico** (semente fixa): manifesto e conteúdo dos arquivos
são reproduzíveis a cada build. A imagem `.dd` pode variar em poucos bytes de
metadados internos do ext4 (timestamps de superbloco) entre versões do
`e2fsprogs`, sem afetar os achados nem o diff. Veja `tests/TESTING.md`.

## Autoria e licença

Desenvolvido por **Daniel Lucas de Oliveira** (Blue Vault — perícia digital).
Licença: ver arquivo [`LICENSE`](LICENSE).
