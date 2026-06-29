# Como subir este projeto para o GitHub

O repositório local já está inicializado e com o **commit inicial** feito
(branch `main`). Falta só criar o repositório remoto e dar `push`. Escolha **uma**
das duas vias abaixo. Em ambas, use **suas próprias credenciais** — nunca cole
um token de acesso (PAT) em chats ou em arquivos versionados.

> A imagem de teste (`tests/crypto_test_image.dd`, ~49 MB) está no `.gitignore`
> de propósito. Ela é reconstruída por quem clonar com `bash tests/build_image.sh`.
> Não force a entrada dela no repo.

---

## Via 1 — GitHub pelo navegador + push (mais simples)

1. Em https://github.com/new crie um repositório **vazio** (sem README, sem
   .gitignore, sem licença — já temos tudo). Nome sugerido:
   `autopsy-crypto-asset-finder`. Escolha **Public** ou **Private**.
2. No seu terminal, dentro da pasta do projeto:

```bash
git remote add origin https://github.com/<SEU-USUARIO>/autopsy-crypto-asset-finder.git
git push -u origin main
```

O Git vai pedir login (use um Personal Access Token como senha, ou o
credential manager / GitHub CLI já autenticado). Pronto.

---

## Via 2 — GitHub CLI (`gh`), cria e sobe num comando

Pré-requisito: `gh auth login` já feito uma vez.

```bash
# dentro da pasta do projeto:
gh repo create autopsy-crypto-asset-finder --source=. --remote=origin --push --private
#   troque --private por --public se quiser público
```

---

## Identidade dos commits

O commit inicial foi feito com o autor **Daniel Lucas de Oliveira
<dev@bluevault.pro>**. Se quiser ajustar para o e-mail que você usa no GitHub:

```bash
git config user.name  "Seu Nome"
git config user.email "voce@exemplo.com"
git commit --amend --reset-author --no-edit     # reescreve o autor do último commit
```

## Licença (decisão sua, antes ou depois do push)

Ainda **não** incluí um arquivo `LICENSE` — essa é uma decisão sua de
propriedade intelectual. Opções comuns:

- **Sem licença / "all rights reserved"** — padrão se você não adicionar nada;
  ninguém pode reusar legalmente sem sua autorização. Bom para manter controle
  (faz sentido para uma ferramenta de consultoria).
- **MIT** — permissiva e simples; qualquer um pode usar/redistribuir, inclusive
  comercialmente.
- **Apache-2.0** — permissiva, com concessão explícita de patentes.
- **GPL-3.0** — copyleft; derivados precisam permanecer abertos.

Me diga qual você prefere que eu gero o `LICENSE` correto e atualizo o rodapé do
README. Se for repositório **público**, considere também adicionar mais tarde um
`CONTRIBUTING.md` e um `SECURITY.md` (posso preparar).

## Depois do primeiro push

```bash
# fluxo normal de mudanças:
git add -A
git commit -m "descrição da mudança"
git push
```
