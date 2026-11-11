import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argos.adapters.bandit import parse_relatorio  # noqa: E402
from argos.schema import Severidade  # noqa: E402

AMOSTRA = {
    "results": [
        {
            "filename": "views.py",
            "line_number": 7,
            "issue_severity": "HIGH",
            "issue_text": "subprocess call with shell=True",
            "test_id": "B602",
            "test_name": "subprocess_popen_with_shell_equals_true",
            "issue_cwe": {"id": 78},
        },
        {
            "filename": "views.py",
            "line_number": 11,
            "issue_severity": "MEDIUM",
            "issue_text": "Use of weak MD5 hash",
            "test_id": "B303",
            "test_name": "hashlib",
            "issue_cwe": {"id": 327},
        },
    ]
}


def test_conta():
    assert len(parse_relatorio(AMOSTRA)) == 2


def test_severidade_mapeada():
    fs = parse_relatorio(AMOSTRA)
    assert fs[0].severidade is Severidade.ALTO
    assert fs[1].severidade is Severidade.MEDIO


def test_cwe_vira_categoria():
    assert parse_relatorio(AMOSTRA)[0].categoria == "CWE-78"


def test_local():
    assert parse_relatorio(AMOSTRA)[0].local == "views.py:7"
