# Guia de teste — CryptoAssetFinder (corpus de ground-truth)

Corpus forense sintético para validar o plugin de ponta a ponta: artefatos
**válidos** e **inválidos** de cada rede, mais um **manifesto** com o resultado
esperado de cada um. Gerador e manifesto são **determinísticos** (semente fixa).

## Arquivos

| Arquivo | Função |
|---|---|
| `gen_corpus.py` | Gera a árvore de evidências + manifesto (auto-valida cada vetor) |
| `build_image.sh` | Reconstrói `crypto_test_image.dd` (MBR + ext4) a partir do gerador |
| `expected_results.csv` | Manifesto: **34 positivos** + 5 negativos |
| `diff_results.py` | Compara o export do Autopsy × manifesto (casa por valor) |
| `validate_new_coins.py` | Afere os validadores das 8 moedas vs libs de referência |

As wordlists ficam em `../plugin/` (já no repositório) — o gerador lê de lá.

### Hashes estáveis (cadeia de custódia)

```
expected_results.csv  sha256 : 68786f7b69d94e6080d0d34d6c463cd8e005e776b3c4e661e87ef3a8b24f7742
plugin/english.txt    sha256 : 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda
```

O manifesto é reproduzível byte-a-byte. A imagem `.dd` **não** é versionada nem
tem hash fixo: o conteúdo é determinístico, mas o `mke2fs` pode gravar uns
poucos bytes de metadados do superbloco ext4 de forma variável entre versões do
`e2fsprogs` — isso não afeta nenhum achado.

## Passos

```bash
cd tests
python3 -m pip install pycryptodome      # o gerador usa Keccak
bash build_image.sh                      # -> crypto_test_image.dd + expected_results.csv
```

1. Autopsy → **New Case** (ou um caso de teste existente).
2. **Add Data Source → Disk Image or VM File → Next**, selecione `crypto_test_image.dd`.
3. Marque **Crypto Asset Finder** na lista de ingest modules e rode.
4. **Tools → Generate Report → Crypto Asset Report** (exporte o CSV).
5. Compare com o manifesto:

```bash
python3 diff_results.py <export_do_autopsy.csv>   # espera 34/34, 0 extras, 0 faltando
```

> A imagem é particionada (MBR, partição ext4 em LBA 2048). O Autopsy prefixa os
> caminhos do manifesto com `/img_crypto_test_image.dd/vol_volN/...` — o
> `diff_results.py` casa por **valor**, então o prefixo não atrapalha.

## O que esperar — 34 positivos

| Rede | Tipo | Qtde |
|---|---|---|
| Bitcoin | endereço (P2PKH, P2SH, bech32, bech32m) | 4 |
| Bitcoin | chave privada WIF (avulsa **+** embutida no `wallet.dat`) | 2 |
| Ethereum/EVM | endereço (inclui USDT/USDC) | 5 |
| Cardano | endereço Shelley (addr1/stake1) | 2 |
| Cardano (Byron) | endereço (`sem_checksum`) | 1 |
| Tron | endereço | 2 |
| Litecoin | endereço (base58 + bech32) | 2 |
| Dogecoin | endereço | 1 |
| XRP | endereço | 1 |
| BIP32 | chave estendida (xprv/xpub) | 2 |
| BIP-39 | seed phrase | 4 |
| Carteira | arquivo de carteira (por nome) | 8 |

> O WIF aparece **2×** (uma vez avulso em `chaves.txt`, uma vez embutido no
> conteúdo binário do `wallet.dat` que o plugin varre) — ambos são achados
> legítimos e estão no manifesto.

## Pontos de verificação críticos

1. **Separação prova/indício.** `checksum_valido`/`bip39_checksum_valido` em
   verde; `sem_checksum` (ETH minúsculo, Cardano Byron) e `bip39_palavras` em
   laranja.
2. **Classificação de token.** Os contratos devem sair como `USDT (ERC-20)`,
   `USDC (ERC-20)` e `USDT (TRC-20)`; o ETH genérico com ticker no arquivo, como
   `USDT (contexto)`; o ETH sem ticker, **sem** token.
3. **Dedup.** O endereço genesis aparece 2× em `notas_carteiras.txt`, mas gera
   **1 só** artifact (mesmo arquivo, mesmo valor).
4. **Teste de borda (1 MiB).** A seed de 24 palavras que cruza a janela de
   leitura deve ser capturada **uma vez** graças ao overlap.
5. **Negativos — AUSENTES** (`falsos_positivos.txt`): BTC/Tron/bech32 corrompidos,
   ETH EIP-55 inválido e string estilo Solana (detector desativado) não devem
   aparecer.
6. **EIP-55 / Keccak.** Os ETH `checksum_valido` só passam com Keccak-256
   (BouncyCastle). Se vierem `sem_checksum`, o BouncyCastle não foi carregado.

## Moedas adicionais

Os validadores de Monero, Cosmos, Stellar, TON, SS58, Algorand, Tezos e BCH são
aferidos isoladamente por `validate_new_coins.py` (contra endereços reais
conhecidos e `stellar-sdk`/`algosdk`/`bech32`). Para incluí-las também no corpus
de imagem, edite as seções de vetores em `gen_corpus.py`.
