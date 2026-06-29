#!/usr/bin/env bash
# Reconstrói a imagem forense de teste (MBR + ext4) a partir do gerador.
# Dependências: python3, pycryptodome, e2fsprogs (mke2fs). Não requer root.
# Uso:  ./build_image.sh [saida.dd]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD="$HERE/build"
EVID="$BUILD/evidence_root"
FSIMG="$BUILD/fs.ext4"
OUT="${1:-$HERE/crypto_test_image.dd}"
UUID="0c0ffee0-1234-5678-9abc-def012345678"   # pinado p/ reprodutibilidade
PART_OFFSET_SECTORS=2048                        # partição começa em 1 MiB
FS_SIZE_MIB=48
export SOURCE_DATE_EPOCH=1700000000             # timestamps determinísticos

command -v mke2fs >/dev/null || { echo "ERRO: instale e2fsprogs (mke2fs)"; exit 1; }

echo "[1/4] gerando árvore de evidências + manifesto (auto-validado)..."
python3 "$HERE/gen_corpus.py"
# fixa todos os timestamps para reprodutibilidade byte-a-byte do ext4
find "$EVID" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} + 2>/dev/null || true

echo "[2/4] criando sistema de arquivos ext4 (mke2fs -d, sem montar)..."
rm -f "$FSIMG"
mke2fs -q -t ext4 -b 4096 -U "$UUID" -d "$EVID" "$FSIMG" "${FS_SIZE_MIB}m"

echo "[3/4] montando MBR + partição Linux (0x83)..."
python3 - "$FSIMG" "$OUT" "$PART_OFFSET_SECTORS" <<'PY'
import sys, os, struct
fsimg, out, off = sys.argv[1], sys.argv[2], int(sys.argv[3])
fs = open(fsimg, 'rb').read()
sector = 512
part_start = off
part_sectors = (len(fs) + sector - 1) // sector
mbr = bytearray(sector)
e = 446                                  # 1ª entrada da tabela de partição
mbr[e+0] = 0x00                          # não-bootável
mbr[e+1:e+4] = bytes([0xfe, 0xff, 0xff]) # CHS start (nominal; LBA é o que vale)
mbr[e+4] = 0x83                          # tipo: Linux
mbr[e+5:e+8] = bytes([0xfe, 0xff, 0xff]) # CHS end (nominal)
struct.pack_into('<I', mbr, e+8,  part_start)
struct.pack_into('<I', mbr, e+12, part_sectors)
mbr[510] = 0x55; mbr[511] = 0xaa         # assinatura
with open(out, 'wb') as f:
    f.write(mbr)
    f.write(b'\x00' * ((part_start - 1) * sector))  # gap pré-partição
    f.write(fs)
print("  imagem: %s  (%d bytes)" % (out, os.path.getsize(out)))
PY

echo "[4/4] checksums:"
sha256sum "$OUT"
md5sum "$OUT"
echo "OK — imagem reconstruída."
echo "Nota: o sha256 pode variar conforme a versão do e2fsprogs (UUID/seed estão"
echo "pinados, mas metadados internos do ext4 podem diferir entre versões). O"
echo "CONTEÚDO é idêntico — o diff contra expected_results.csv deve bater 100%."
