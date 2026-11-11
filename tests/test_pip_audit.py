import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argos.adapters.pip_audit import parse_relatorio  # noqa: E402
from argos.schema import Severidade, FixTipo  # noqa: E402

AMOSTRA = {
    "dependencies": [
        {
            "name": "requests",
            "version": "2.19.1",
            "vulns": [
                {
                    "id": "PYSEC-2018-28",
                    "fix_versions": ["2.20.0"],
                    "aliases": ["CVE-2018-18074"],
                    "description": "Credential leak on redirect.",
                }
            ],
        },
        {"name": "segura", "version": "1.0", "vulns": []},
        {
            "name": "semfix",
            "version": "0.1",
            "vulns": [{"id": "PYSEC-X", "fix_versions": [], "aliases": [], "description": "sem fix"}],
        },
    ]
}


def test_um_finding_por_vuln():
    assert len(parse_relatorio(AMOSTRA)) == 2  # 'segura' nao conta


def test_usa_cve_quando_tem_alias():
    assert parse_relatorio(AMOSTRA)[0].categoria == "CVE-2018-18074"


def test_fix_deterministico_com_versao():
    f = parse_relatorio(AMOSTRA)[0]
    assert f.fix.tipo is FixTipo.DETERMINISTICO
    assert f.fix.patch == "requests==2.20.0"


def test_sem_fix_vira_ia():
    f = parse_relatorio(AMOSTRA)[1]  # semfix
    assert f.fix.tipo is FixTipo.IA


def test_severidade_default_alto():
    assert parse_relatorio(AMOSTRA)[0].severidade is Severidade.ALTO


def test_local_junta_arquivo_e_pacote():
    assert parse_relatorio(AMOSTRA)[0].local == "requirements.txt:requests"
