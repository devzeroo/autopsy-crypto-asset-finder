# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/).

## [Não lançado]

### Adicionado
- 8 novas redes com checksum validável: Monero, Cosmos (e ecossistema),
  Stellar (endereço `G` e chave secreta `S`), TON, Polkadot/Kusama/Substrate
  (SS58), Algorand, Tezos e Bitcoin Cash (CashAddr).
- `tests/build_image.sh` — reconstrução determinística da imagem de teste
  (MBR + ext4) a partir do gerador, sem root.
- `tests/validate_new_coins.py` — aferição dos validadores contra endereços
  reais conhecidos e bibliotecas de referência (`stellar-sdk`, `algosdk`, `bech32`).

### Alterado
- `tests/gen_corpus.py` agora é **determinístico** (semente fixa) — manifesto e
  conteúdo reproduzíveis a cada build.
- Caminhos dos scripts de teste parametrizados (relativos / via argumento), sem
  mais dependência de `/tmp`.
- Estrutura reorganizada em `plugin/` (instalável) e `tests/` (validação).
- Wordlists BIP-39 `english.txt` e `portuguese.txt` passam a acompanhar o repo.

## [1.0.0]

### Adicionado
- Núcleo do módulo de ingestão e relatório para Autopsy/Sleuth Kit.
- Detecção de endereços (BTC, ETH/EVM, Cardano, Tron, Litecoin, Dogecoin, XRP),
  chaves (WIF, estendidas), seeds BIP-39 multi-idioma e arquivos de carteira.
- Classificação de token USDT/USDC por contrato e contexto.
- Corpus de ground-truth auto-validado e manifesto de resultados esperados.
