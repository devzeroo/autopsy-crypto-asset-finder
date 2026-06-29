# -*- coding: utf-8 -*-
#
# CryptoAssetReport - Autopsy General Report Module (Jython 2.7)
# -----------------------------------------------------------------------------
# Consolida os artifacts TSK_CRYPTO_ASSET produzidos pelo CryptoAssetFinder
# em dois relatorios:
#   - crypto_assets.csv  (planilha completa)
#   - crypto_assets.html (visao por rede e nivel de validacao)
#
# Roda em nivel de caso (Tools -> Generate Report), normalmente depois que o
# perito revisou os achados de ingestao.
# -----------------------------------------------------------------------------

import os
import csv
import inspect

from java.util.logging import Level
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.report import GeneralReportModuleAdapter

MODULE_NAME = "CryptoAssetReport"

# Nomes dos atributos definidos pelo modulo de ingestao
A_VALUE = "TSK_CRYPTO_VALUE"
A_NET = "TSK_CRYPTO_NETWORK"
A_KIND = "TSK_CRYPTO_KIND"
A_VALID = "TSK_CRYPTO_VALIDATION"
A_TOKEN = "TSK_CRYPTO_TOKEN"
A_OFFSET = "TSK_CRYPTO_OFFSET"


def _esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            if s else "")


class CryptoAssetReportModule(GeneralReportModuleAdapter):

    _logger = Logger.getLogger(MODULE_NAME)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__,
                          inspect.stack()[1][3], msg)

    def getName(self):
        return "Crypto Asset Report"

    def getDescription(self):
        return ("Consolida os achados de criptomoedas (TSK_CRYPTO_ASSET) em "
                "relatorios CSV e HTML, separando prova de indicio pelo status "
                "de validacao de checksum.")

    def getRelativeFilePath(self):
        return "crypto_assets.html"

    # Compatibilidade: versoes recentes passam GeneralReportSettings;
    # antigas passam a string do diretorio.
    def generateReport(self, *args):
        progressBar = args[-1]
        first = args[0]
        if isinstance(first, basestring):
            report_dir = first
        else:
            report_dir = first.getReportDirectoryPath()

        progressBar.setIndeterminate(True)
        progressBar.start()
        progressBar.updateStatusLabel("Consultando artifacts de cripto...")

        skCase = Case.getCurrentCase().getSleuthkitCase()
        rows = self._collect(skCase)

        csv_path = os.path.join(report_dir, "crypto_assets.csv")
        html_path = os.path.join(report_dir, "crypto_assets.html")
        self._write_csv(csv_path, rows)
        self._write_html(html_path, rows)

        Case.getCurrentCase().addReport(html_path, MODULE_NAME, "Crypto Assets (HTML)")
        Case.getCurrentCase().addReport(csv_path, MODULE_NAME, "Crypto Assets (CSV)")

        progressBar.complete(self._RESULT_OK())

    def _RESULT_OK(self):
        # Import tardio para compat. de pacote entre versoes
        from org.sleuthkit.autopsy.report import ReportProgressPanel
        return ReportProgressPanel.ReportStatus.COMPLETE

    def _collect(self, skCase):
        rows = []
        try:
            arts = skCase.getBlackboardArtifacts("TSK_CRYPTO_ASSET")
        except Exception as e:
            self.log(Level.WARNING, "Nenhum artifact TSK_CRYPTO_ASSET: " + str(e))
            return rows

        for art in arts:
            data = {A_VALUE: "", A_NET: "", A_KIND: "", A_VALID: "",
                    A_TOKEN: "", A_OFFSET: ""}
            for attr in art.getAttributes():
                name = attr.getAttributeType().getTypeName()
                if name == A_OFFSET:
                    data[name] = str(attr.getValueLong())
                elif name in data:
                    data[name] = attr.getValueString()
            # caminho do arquivo de origem
            try:
                src = art.getSleuthkitCase().getAbstractFileById(art.getObjectID())
                path = src.getUniquePath() if src else ""
            except Exception:
                path = ""
            rows.append((data[A_NET], data[A_KIND], data[A_VALUE],
                         data[A_VALID], data[A_TOKEN], data[A_OFFSET], path))

        # ordena: rede, depois validacao (validos primeiro)
        order = {"checksum_valido": 0, "bip39_checksum_valido": 0,
                 "match_por_nome": 1, "sem_checksum": 2, "bip39_palavras": 2}
        rows.sort(key=lambda r: (r[0], order.get(r[3], 9), r[1]))
        return rows

    def _write_csv(self, path, rows):
        fh = open(path, "wb")
        try:
            w = csv.writer(fh)
            w.writerow(["Rede", "Tipo", "Valor", "Validacao", "Token",
                        "Offset", "Arquivo"])
            for r in rows:
                w.writerow([(c or "").encode("utf-8") for c in r])
        finally:
            fh.close()

    def _write_html(self, path, rows):
        # estatisticas
        by_net = {}
        valids = 0
        for r in rows:
            by_net[r[0]] = by_net.get(r[0], 0) + 1
            if r[3] in ("checksum_valido", "bip39_checksum_valido"):
                valids += 1

        fh = open(path, "w")
        try:
            fh.write("<!DOCTYPE html><html><head><meta charset='utf-8'>")
            fh.write("<title>Crypto Assets</title><style>")
            fh.write("body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1a1a1a}")
            fh.write("h1{font-size:20px}table{border-collapse:collapse;width:100%;font-size:13px}")
            fh.write("th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;"
                     "word-break:break-all}")
            fh.write("th{background:#f0f2f5}")
            fh.write(".ok{color:#0a7d28;font-weight:600}.warn{color:#b06a00}")
            fh.write(".sum{margin:10px 0 20px;padding:10px 14px;background:#f7f9fc;"
                     "border:1px solid #e0e6ef;border-radius:6px}")
            fh.write("</style></head><body>")
            fh.write("<h1>Achados de Criptomoedas</h1>")
            fh.write("<div class='sum'><b>Total:</b> %d &nbsp;|&nbsp; "
                     "<b>Com checksum validado:</b> %d<br>" % (len(rows), valids))
            parts = ["%s: %d" % (_esc(k), v) for k, v in sorted(by_net.items())]
            fh.write("<b>Por rede:</b> " + " &nbsp; ".join(parts) + "</div>")

            fh.write("<table><tr><th>Rede</th><th>Tipo</th><th>Valor</th>"
                     "<th>Validacao</th><th>Token</th><th>Offset</th>"
                     "<th>Arquivo</th></tr>")
            for r in rows:
                cls = "ok" if r[3] in ("checksum_valido", "bip39_checksum_valido") else "warn"
                fh.write("<tr><td>%s</td><td>%s</td><td>%s</td>"
                         "<td class='%s'>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                         % (_esc(r[0]), _esc(r[1]), _esc(r[2]), cls,
                            _esc(r[3]), _esc(r[4]), _esc(r[5]), _esc(r[6])))
            fh.write("</table></body></html>")
        finally:
            fh.close()
