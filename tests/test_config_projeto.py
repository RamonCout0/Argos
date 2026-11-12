"""Checagem de configuracao do projeto (v2.1): Django/DRF, Angular e .env."""
import json
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argos.adapters.config_projeto import Checagem, ConfigAdapter  # noqa: E402
from argos.adapters.base import Contexto  # noqa: E402
from argos.schema import Severidade  # noqa: E402

SETTINGS_RUIM = """\
import os
INSTALLED_APPS = ['django.contrib.admin', 'rest_framework', 'corsheaders']
SECRET_KEY = 'django-insecure-abcdefghijklmnopqrstuvwxyz0123'
ALLOWED_HOSTS = ['*']
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True
"""

SETTINGS_BOM = """\
import os
INSTALLED_APPS = ['django.contrib.admin', 'rest_framework']
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']
ALLOWED_HOSTS = ['tevejo.com.br']
CORS_ALLOWED_ORIGINS = ['http://localhost:4200']
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.IsAuthenticated'],
}
"""

URLS = """\
from django.contrib import admin
from django.urls import path
urlpatterns = [path('admin/', admin.site.urls)]
class Publica:
    permission_classes = [AllowAny]
"""


def _escrever(raiz, rel, texto):
    caminho = os.path.join(raiz, rel)
    os.makedirs(os.path.dirname(caminho), exist_ok=True)
    with open(caminho, "w", encoding="utf-8") as fp:
        fp.write(texto)


def _por_cat(achados):
    d = {}
    for f in achados:
        d.setdefault(f.categoria, []).append(f)
    return d


def test_django_inseguro(tmp_path):
    _escrever(tmp_path, "backend/core/settings.py", SETTINGS_RUIM)
    _escrever(tmp_path, "backend/core/urls.py", URLS)
    cats = _por_cat(Checagem(str(tmp_path)).rodar())
    assert cats["CWE-798"][0].severidade == Severidade.ALTO
    assert "abcdefghij" not in cats["CWE-798"][0].evidencia     # chave mascarada
    assert "CWE-16" in cats
    assert cats["CWE-942"][0].severidade == Severidade.ALTO      # tudo + credenciais
    drf = [f for f in cats["CWE-862"] if "DEFAULT_PERMISSION" in f.titulo]
    assert drf and drf[0].fix.patch and "IsAuthenticated" in drf[0].fix.patch
    assert "ARGOS-ADMIN-PADRAO" in cats
    assert any("AllowAny" in f.titulo for f in cats["CWE-862"])
    assert cats["CWE-798"][0].local.startswith("backend/core/settings.py:")


def test_django_bem_configurado_fica_quieto(tmp_path):
    _escrever(tmp_path, "core/settings.py", SETTINGS_BOM)
    assert Checagem(str(tmp_path)).rodar() == []


def test_drf_allowany_como_padrao(tmp_path):
    _escrever(tmp_path, "core/settings.py", SETTINGS_BOM.replace("IsAuthenticated", "AllowAny"))
    achados = Checagem(str(tmp_path)).rodar()
    assert [f.categoria for f in achados] == ["CWE-862"]


def test_angular(tmp_path):
    cfg = {"projects": {"front": {"architect": {"build": {"configurations": {
        "production": {"sourceMap": True}}}}}}}
    _escrever(tmp_path, "front/angular.json", json.dumps(cfg))
    _escrever(tmp_path, "front/src/environments/environment.ts",
              "export const environment = {\n  production: false,\n"
              "  firebaseApiKey: 'AIzaSyFALSO1234567890',\n  clientSecret: 'segredo-muito-falso-123',\n};\n")
    achados = Checagem(str(tmp_path)).rodar()
    sev = {(f.categoria, f.severidade) for f in achados}
    assert ("CWE-540", Severidade.BAIXO) in sev
    assert ("CWE-798", Severidade.ALTO) in sev        # clientSecret
    assert ("CWE-798", Severidade.INFO) in sev        # Firebase e publico por design
    assert all("muito-falso" not in f.evidencia for f in achados)


def test_env_fora_do_gitignore(tmp_path):
    _escrever(tmp_path, ".env", "SENHA=x\n")
    _escrever(tmp_path, ".env.example", "SENHA=\n")   # exemplo nao conta
    achados = Checagem(str(tmp_path)).rodar()
    assert len(achados) == 1 and achados[0].severidade == Severidade.ALTO
    _escrever(tmp_path, ".gitignore", ".env\n")
    assert Checagem(str(tmp_path)).rodar() == []


@pytest.mark.skipif(not shutil.which("git"), reason="git nao instalado")
def test_env_commitado_e_critico(tmp_path):
    _escrever(tmp_path, ".env", "SENHA=x\n")
    git = ["git", "-C", str(tmp_path), "-c", "user.email=t@t", "-c", "user.name=t"]
    subprocess.run(git + ["init", "-q"], check=True)
    subprocess.run(git + ["add", ".env"], check=True)
    subprocess.run(git + ["commit", "-qm", "ops"], check=True)
    _escrever(tmp_path, ".gitignore", ".env\n")        # ignorar depois nao resolve
    achados = Checagem(str(tmp_path)).rodar()
    assert achados[0].severidade == Severidade.CRITICO
    assert "git rm --cached" in achados[0].fix.patch


def test_ignora_node_modules(tmp_path):
    _escrever(tmp_path, "node_modules/pacote/settings.py", SETTINGS_RUIM)
    assert Checagem(str(tmp_path)).rodar() == []


def test_adapter_pasta_inexistente():
    assert ConfigAdapter().escanear(Contexto(projeto="/nao/existe")) == []
