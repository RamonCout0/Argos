import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argos.adapters.gitleaks import parse_relatorio, _mascarar  # noqa: E402
from argos.schema import Severidade, Lente, Status  # noqa: E402

# Amostra no formato que o gitleaks cospe (campos reais do report JSON).
AMOSTRA = [
    {
        "RuleID": "github-pat",
        "Description": "GitHub Personal Access Token",
        "File": "config/settings.py",
        "StartLine": 7,
        "Secret": "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB",
    },
    {
        "RuleID": "aws-access-token",
        "Description": "AWS Secret Key",
        "File": "config/settings.py",
        "StartLine": 9,
        "Secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",
    },
]


def test_parse_gera_um_finding_por_vazamento():
    findings = parse_relatorio(AMOSTRA)
    assert len(findings) == 2


def test_segredo_e_sempre_critico():
    for f in parse_relatorio(AMOSTRA):
        assert f.severidade is Severidade.CRITICO
        assert f.categoria == "CWE-798"
        assert f.status is Status.ABERTO


def test_local_junta_arquivo_e_linha():
    f = parse_relatorio(AMOSTRA)[0]
    assert f.local == "config/settings.py:7"


def test_lentes_critico_e_lgpd():
    f = parse_relatorio(AMOSTRA)[0]
    assert Lente.CRITICO in f.lentes
    assert Lente.LGPD in f.lentes


def test_segredo_nunca_aparece_cru_na_evidencia():
    # o segredo inteiro JAMAIS pode vazar no relatorio
    for item, f in zip(AMOSTRA, parse_relatorio(AMOSTRA)):
        assert item["Secret"] not in f.evidencia


def test_mascara_encurta_e_esconde_o_meio():
    assert _mascarar("ghp_0123456789abcdefAB") == "ghp_***AB"
    assert _mascarar("") == "(oculto)"


def test_parse_lida_com_campos_faltando():
    f = parse_relatorio([{"RuleID": "x"}])[0]
    assert f.local == "?:?"


def test_lista_vazia_nao_quebra():
    assert parse_relatorio([]) == []
