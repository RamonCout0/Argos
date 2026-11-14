"""v2.2: OSV-Scanner, npm audit, Django check --deploy, Trivy e histórico do gitleaks."""
import os
import subprocess
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argos.adapters import dependencias as dep, django_deploy as dj, trivy as tv, gitleaks as gl  # noqa: E402
from argos.adapters.base import Contexto  # noqa: E402
from argos.core.dedup import deduplicar  # noqa: E402
from argos.adapters.pip_audit import parse_relatorio as parse_pip  # noqa: E402
from argos.ai.templates import explicacao_base, DEPENDENCIA, DOCKER  # noqa: E402
from argos.schema import Severidade  # noqa: E402

OSV = {"results": [
    {"source": {"path": "/proj/front/package-lock.json", "type": "lockfile"},
     "packages": [{"package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
                   "vulnerabilities": [{"id": "GHSA-p6mc-m468-83gw", "aliases": ["CVE-2020-8203"],
                                        "summary": "Prototype Pollution in lodash",
                                        "affected": [{"package": {"name": "lodash"},
                                                      "ranges": [{"events": [{"introduced": "0"},
                                                                             {"fixed": "4.17.19"}]}]}]}],
                   "groups": [{"ids": ["GHSA-p6mc-m468-83gw"], "max_severity": "7.4"}]}]},
    {"source": {"path": "/proj/requirements.txt", "type": "lockfile"},
     "packages": [{"package": {"name": "django", "version": "3.2.0", "ecosystem": "PyPI"},
                   "vulnerabilities": [{"id": "PYSEC-2021-98", "aliases": ["CVE-2021-31542"],
                                        "database_specific": {"severity": "CRITICAL"}}],
                   "groups": [{"ids": ["PYSEC-2021-98"]}]}]},
]}


def test_osv_traduz_severidade_versao_e_caminho():
    fs = dep.parse_osv(OSV, raiz="/proj")
    lodash, django = fs
    assert lodash.categoria == "CVE-2020-8203" and lodash.severidade == Severidade.ALTO
    assert lodash.local == "front/package-lock.json:lodash"
    assert lodash.fix.patch == "lodash@4.17.19"
    assert django.severidade == Severidade.CRITICO and django.fix.tipo.value == "ia"


def test_osv_e_pip_audit_viram_um_achado_so():
    pip = parse_pip({"dependencies": [{"name": "django", "version": "3.2.0", "vulns": [
        {"id": "PYSEC-2021-98", "aliases": ["CVE-2021-31542"], "fix_versions": ["3.2.1"]}]}]})
    osv = [f for f in dep.parse_osv(OSV, raiz="/proj") if "django" in f.titulo]
    juntos = deduplicar(pip + osv)
    assert len(juntos) == 1 and "osv-scanner" in juntos[0].origem and "pip-audit" in juntos[0].origem


def test_npm_audit_parse():
    dados = {"vulnerabilities": {
        "axios": {"severity": "high", "range": "<0.21.1", "fixAvailable": {"name": "axios", "version": "1.6.0",
                                                                           "isSemVerMajor": True},
                  "via": [{"title": "SSRF in axios", "url": "https://github.com/advisories/GHSA-4w2v-q235-vp99"}]},
        "herdado": {"severity": "high", "via": ["axios"], "fixAvailable": True}}}
    fs = dep.parse_npm(dados, "front/package-lock.json")
    assert len(fs) == 1
    f = fs[0]
    assert f.categoria == "GHSA-4w2v-q235-vp99" and f.fix.patch == "npm install axios@1.6.0"
    assert "testar antes" in f.fix.descricao


def test_npm_audit_fica_quieto_se_o_osv_existe(monkeypatch, tmp_path):
    monkeypatch.setattr(dep, "achar_programa", lambda n: "/bin/" + n)
    assert dep.NpmAuditAdapter().escanear(Contexto(projeto=str(tmp_path))) == []


def test_explicacao_de_dependencia_e_docker():
    assert explicacao_base("CVE-2020-8203") == DEPENDENCIA
    assert explicacao_base("GHSA-xxxx") == DEPENDENCIA
    assert explicacao_base("TRIVY-DS002") == DOCKER


SAIDA_CHECK = textwrap.dedent("""\
    System check identified some issues:

    WARNINGS:
    ?: (security.W004) You have not set a value for the SECURE_HSTS_SECONDS setting. If your entire site is served only over SSL, you may want to consider setting a value.
    ?: (security.W009) Your SECRET_KEY has less than 50 characters, less than 5 unique characters, or it's prefixed with 'django-insecure-'.
    ?: (security.W018) You should not have DEBUG set to True in deployment.

    System check identified 3 issues (0 silenced).
    """)


def test_check_deploy_modo_dev_nao_trava_o_selo():
    fs = dj.parse_check(SAIDA_CHECK, producao=False)
    assert [f.local.split(".")[-1] for f in fs] == ["W004", "W009", "W018"]
    assert all(f.severidade not in (Severidade.CRITICO, Severidade.ALTO) for f in fs)
    assert all(f.titulo.endswith("(em produção)") for f in fs)


def test_check_deploy_modo_producao_usa_a_gravidade_real():
    fs = {f.local.split(".")[-1]: f for f in dj.parse_check(SAIDA_CHECK, producao=True)}
    assert fs["W018"].severidade == Severidade.ALTO and fs["W009"].severidade == Severidade.ALTO
    assert fs["W004"].severidade == Severidade.BAIXO


def test_acha_manage_e_venv_do_projeto(tmp_path):
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "manage.py").write_text("")
    rel = ("Scripts", "python.exe") if os.name == "nt" else ("bin", "python")
    py = tmp_path.joinpath("venv", *rel)
    py.parent.mkdir(parents=True)
    py.write_text("")
    manage = dj.achar_manage(str(tmp_path))
    assert manage.endswith(os.path.join("backend", "manage.py"))
    assert dj.python_do_projeto(str(tmp_path), os.path.dirname(manage)) == str(py)


def test_sem_django_nao_faz_nada(tmp_path):
    assert dj.DjangoDeployAdapter().escanear(Contexto(projeto=str(tmp_path))) == []


@pytest.mark.skipif(subprocess.run([sys.executable, "-c", "import django"]).returncode != 0,
                    reason="Django nao instalado")
def test_check_deploy_de_verdade(tmp_path):
    (tmp_path / "manage.py").write_text(textwrap.dedent("""\
        import os, sys
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "site_x.settings")
        from django.core.management import execute_from_command_line
        execute_from_command_line(sys.argv)
        """))
    (tmp_path / "site_x").mkdir()
    (tmp_path / "site_x" / "__init__.py").write_text("")
    (tmp_path / "site_x" / "settings.py").write_text(textwrap.dedent("""\
        SECRET_KEY = "django-insecure-curta"
        DEBUG = True
        ALLOWED_HOSTS = []
        INSTALLED_APPS = []
        MIDDLEWARE = []
        ROOT_URLCONF = "site_x.urls"
        """))
    (tmp_path / "site_x" / "urls.py").write_text("urlpatterns = []\n")
    fs = dj.DjangoDeployAdapter().escanear(Contexto(projeto=str(tmp_path)))
    codigos = {f.local.split(".")[-1] for f in fs}
    assert {"W001", "W009", "W018"} <= codigos


TRIVY = {"Results": [{"Target": "/p/Dockerfile", "Misconfigurations": [
    {"ID": "DS002", "AVDID": "AVD-DS-0002", "Title": "Image user should not be 'root'",
     "Message": "Specify at least 1 USER command", "Resolution": "Add 'USER <non root user>'",
     "Severity": "HIGH", "Status": "FAIL", "CauseMetadata": {"StartLine": 1}},
    {"ID": "DS026", "Title": "ok", "Severity": "LOW", "Status": "PASS"}]}]}


def test_trivy_parse():
    fs = tv.parse_trivy(TRIVY, raiz="/p")
    assert len(fs) == 1
    assert fs[0].local == "Dockerfile:1" and fs[0].severidade == Severidade.ALTO
    assert fs[0].categoria == "TRIVY-DS002" and "USER" in fs[0].fix.descricao


def test_trivy_sem_docker_nao_roda(tmp_path, monkeypatch):
    monkeypatch.setattr(tv, "achar_programa", lambda n: None)
    assert tv.TrivyAdapter().escanear(Contexto(projeto=str(tmp_path))) == []


def test_gitleaks_historico_so_traz_o_que_sumiu(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    atual = [{"File": str(tmp_path / "app.py"), "StartLine": 3, "RuleID": "generic-api-key", "Secret": "abcd1234zz"}]
    historico = atual + [
        {"File": "config_antiga.py", "StartLine": 9, "RuleID": "aws-access-token",
         "Secret": "AKIAFALSOFALSO12", "Commit": "9f8e7d6c5b"},
        {"File": "config_antiga.py", "StartLine": 9, "RuleID": "aws-access-token",
         "Secret": "AKIAFALSOFALSO12", "Commit": "1111111111"}]
    ad = gl.GitleaksAdapter()
    monkeypatch.setattr(gl, "_achar_gitleaks", lambda: "gitleaks")
    monkeypatch.setattr(ad, "_suporta_dir", lambda: True)
    monkeypatch.setattr(ad, "_rodar", lambda cmd, rel: historico if cmd[1] == "git" else atual)
    fs = ad.escanear(Contexto(projeto=str(tmp_path)))
    assert len(fs) == 2
    velho = fs[1]
    assert velho.titulo.endswith("(no histórico do git)")
    assert "commit 9f8e7d6" in velho.evidencia and "AKIAFALSO" not in velho.evidencia
    assert "TROCAR" in velho.fix.descricao
