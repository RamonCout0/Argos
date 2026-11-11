import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argos.adapters.semgrep import parse_relatorio, _win_para_wsl, _wsl_para_win  # noqa: E402
from argos.schema import Severidade  # noqa: E402

AMOSTRA = {
    "results": [
        {
            "check_id": "python.lang.security.audit.dangerous-subprocess-use",
            "path": "/mnt/c/Users/x/Argos/exemplos/projeto_vulneravel/views.py",
            "start": {"line": 7},
            "extra": {
                "severity": "ERROR",
                "message": "Detected subprocess with shell=True",
                "metadata": {"cwe": ["CWE-78: OS Command Injection"]},
            },
        },
        {
            "check_id": "python.lang.best-practice.something",
            "path": "a.py",
            "start": {"line": 2},
            "extra": {"severity": "WARNING", "message": "warn", "metadata": {}},
        },
    ]
}


def test_conta():
    assert len(parse_relatorio(AMOSTRA)) == 2


def test_severidade_map():
    fs = parse_relatorio(AMOSTRA)
    assert fs[0].severidade is Severidade.ALTO     # ERROR
    assert fs[1].severidade is Severidade.MEDIO    # WARNING


def test_cwe_extraido_do_metadata():
    assert parse_relatorio(AMOSTRA)[0].categoria == "CWE-78"


def test_traducao_de_path_aplicada_na_exibicao():
    f = parse_relatorio(AMOSTRA, traduzir=_wsl_para_win)[0]
    assert f.local.startswith("C:\\Users\\x\\Argos")


# --- tradução de caminho Windows <-> WSL ---

def test_win_para_wsl_absoluto():
    assert _win_para_wsl("C:\\Users\\x\\p") == "/mnt/c/Users/x/p"


def test_win_para_wsl_relativo_so_troca_barra():
    assert _win_para_wsl("exemplos\\proj") == "exemplos/proj"


def test_wsl_para_win_absoluto():
    assert _wsl_para_win("/mnt/c/Users/x") == "C:\\Users\\x"


def test_wsl_para_win_relativo_volta_igual():
    assert _wsl_para_win("rel/path") == "rel/path"
