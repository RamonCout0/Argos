"""
Argos — configuração do projeto (v2.1), lida direto do código.

Complementa a trilha web: o que dá pra ver sem rodar nada.
  - .env fora do .gitignore, ou pior, já commitado
  - Django: SECRET_KEY no código, ALLOWED_HOSTS = ['*'], CORS liberado geral,
    admin no endereço padrão, DRF sem DEFAULT_PERMISSION_CLASSES (o padrão
    dele é AllowAny: todo endpoint aberto se a view não disser o contrário)
  - Angular: segredo no environment.ts (vai pro navegador) e source map em produção

Python puro, roda sozinho dentro do `scan`/`auditar` de uma pasta.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import subprocess

from .base import Adapter, Contexto
from ..core import progresso
from ..schema import Finding, Severidade, Lente, Fix, FixTipo

IGNORAR = {"node_modules", ".git", "venv", ".venv", "env", "__pycache__", "dist", "build",
           ".angular", "staticfiles", "site-packages", ".argos_cache"}
MAX_ARQUIVOS = 6000
EXEMPLOS_ENV = (".env.example", ".env.exemplo", ".env.sample", ".env.template", ".env.dist")
CRIT, ALTO, MEDIO, BAIXO, INFO = (Severidade.CRITICO, Severidade.ALTO, Severidade.MEDIO,
                                  Severidade.BAIXO, Severidade.INFO)


def _arquivos(raiz: str):
    n = 0
    for pasta, dirs, nomes in os.walk(raiz):
        dirs[:] = [d for d in dirs if d not in IGNORAR and not d.startswith(".") or d in (".github",)]
        for nome in nomes:
            n += 1
            if n > MAX_ARQUIVOS:
                return
            yield os.path.join(pasta, nome)


def _ler(caminho: str, limite: int = 400_000) -> str:
    try:
        with open(caminho, encoding="utf-8", errors="replace") as fp:
            return fp.read(limite)
    except OSError:
        return ""


def _rel(raiz: str, caminho: str) -> str:
    return os.path.relpath(caminho, raiz).replace("\\", "/")


def _linha(texto: str, pos: int) -> int:
    return texto.count("\n", 0, pos) + 1


def _ignorado(raiz: str, rel: str) -> bool:
    gi = os.path.join(raiz, ".gitignore")
    padroes = [l.strip() for l in _ler(gi).splitlines() if l.strip() and not l.startswith("#")]
    nome = os.path.basename(rel)
    for p in padroes:
        if p.startswith("!"):
            continue
        p = p.lstrip("/").rstrip("/")
        if fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(nome, p) or fnmatch.fnmatch(rel, "*/" + p):
            return True
    return False


def _commitado(raiz: str, rel: str) -> bool:
    if not os.path.isdir(os.path.join(raiz, ".git")) or not shutil.which("git"):
        return False
    try:
        r = subprocess.run(["git", "-C", raiz, "ls-files", "--error-unmatch", rel],
                           capture_output=True, text=True, timeout=15)
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


class Checagem:
    def __init__(self, raiz: str):
        self.raiz = raiz
        self.achados: list[Finding] = []

    def add(self, titulo, sev, cat, rel, linha, evidencia, fix, lentes=None, tipo=FixTipo.IA, patch=None):
        local = f"{rel}:{linha}" if linha else rel
        self.achados.append(Finding(
            id=f"CFG-{len(self.achados) + 1:03d}", titulo=titulo, severidade=sev, categoria=cat,
            origem="argos-config", local=local, evidencia=evidencia, lentes=list(lentes or []),
            fix=Fix(tipo, fix, patch), verificacao="re-rodar o scan -> achado some"))

    def rodar(self) -> list[Finding]:
        arquivos = list(_arquivos(self.raiz))
        progresso.avisar(f"config: {len(arquivos)} arquivo(s) no projeto", "info")
        self._env(arquivos)
        for a in arquivos:
            nome = os.path.basename(a)
            if nome in ("settings.py", "urls.py", "angular.json") or "environments" in a:
                progresso.avisar(f"config: lendo {_rel(self.raiz, a)}", "info")
            if nome == "settings.py" or (os.path.basename(os.path.dirname(a)) == "settings" and nome.endswith(".py")):
                self._django_settings(a)
            elif nome == "urls.py":
                self._django_urls(a)
            elif nome == "angular.json":
                self._angular_json(a)
            elif re.search(r"[\\/]environments[\\/]environment[^\\/]*\.ts$", a):
                self._angular_env(a)
        return self.achados

    # ---- .env
    def _env(self, arquivos):
        for a in arquivos:
            nome = os.path.basename(a)
            if not (nome == ".env" or nome.startswith(".env.")) or nome in EXEMPLOS_ENV:
                continue
            rel = _rel(self.raiz, a)
            if _commitado(self.raiz, rel):
                self.add(f"{rel} já foi commitado no git", CRIT, "CWE-538", rel, 0,
                         "o arquivo está no histórico do repositório; quem clonar tem as senhas",
                         "Remover do git (git rm --cached), adicionar ao .gitignore e TROCAR todos os "
                         "segredos dele: o histórico continua tendo a versão antiga.",
                         patch=f"git rm --cached {rel}\necho \"{nome}\" >> .gitignore")
            elif not _ignorado(self.raiz, rel):
                self.add(f"{rel} fora do .gitignore", ALTO, "CWE-538", rel, 0,
                         "o próximo 'git add .' manda as senhas pro repositório",
                         "Adicionar o .env ao .gitignore antes do próximo commit.",
                         tipo=FixTipo.DETERMINISTICO, patch=".env\n.env.*\n!.env.example")

    # ---- Django
    def _django_settings(self, a):
        t = _ler(a)
        if "django" not in t.lower() and "INSTALLED_APPS" not in t:
            return
        rel = _rel(self.raiz, a)
        m = re.search(r"""^SECRET_KEY\s*=\s*["']([^"']{20,})["']""", t, re.M)
        if m:
            self.add("SECRET_KEY do Django escrita no código", ALTO, "CWE-798", rel, _linha(t, m.start()),
                     f"SECRET_KEY = '{m.group(1)[:6]}***' (com ela dá pra forjar sessão e tokens)",
                     "Ler de variável de ambiente e gerar uma chave nova pra produção.",
                     patch="SECRET_KEY = os.environ['DJANGO_SECRET_KEY']")
        m = re.search(r"""^ALLOWED_HOSTS\s*=\s*\[[^\]]*["']\*["']""", t, re.M)
        if m:
            self.add("ALLOWED_HOSTS aceita qualquer domínio", MEDIO, "CWE-16", rel, _linha(t, m.start()),
                     "ALLOWED_HOSTS = ['*'] (abre espaço pra ataque de Host header)",
                     "Listar só os domínios reais (ex.: ['gatunoestrelas.com.br', '.up.railway.app']).")
        m = re.search(r"^(CORS_ALLOW_ALL_ORIGINS|CORS_ORIGIN_ALLOW_ALL)\s*=\s*True", t, re.M)
        if m:
            cred = re.search(r"^CORS_ALLOW_CREDENTIALS\s*=\s*True", t, re.M)
            self.add("CORS liberado pra qualquer origem" + (" com credenciais" if cred else ""),
                     ALTO if cred else MEDIO, "CWE-942", rel, _linha(t, m.start()),
                     f"{m.group(1)} = True" + (" e CORS_ALLOW_CREDENTIALS = True" if cred else ""),
                     "Usar CORS_ALLOWED_ORIGINS com a lista do teu front (ex.: http://localhost:4200 no dev).")
        if re.search(r"""["']rest_framework["']""", t):
            bloco = re.search(r"DEFAULT_PERMISSION_CLASSES[\"']?\s*:\s*[\[(]([^\])]*)", t)
            if not bloco:
                self.add("DRF sem DEFAULT_PERMISSION_CLASSES: o padrão libera todo endpoint", MEDIO, "CWE-862",
                         rel, 0, "sem essa configuração o DRF usa AllowAny; toda view sem permission_classes "
                         "fica aberta pra quem mandar a requisição direto (ex.: pelo Burp)",
                         "Definir o padrão fechado e abrir só o que for público.",
                         patch="REST_FRAMEWORK = {\n    'DEFAULT_PERMISSION_CLASSES': [\n"
                               "        'rest_framework.permissions.IsAuthenticated',\n    ],\n}")
            elif "AllowAny" in bloco.group(1):
                self.add("DRF com AllowAny como permissão padrão", MEDIO, "CWE-862", rel,
                         _linha(t, bloco.start()), "DEFAULT_PERMISSION_CLASSES inclui AllowAny",
                         "Trocar o padrão por IsAuthenticated e abrir só as views públicas.")

    def _django_urls(self, a):
        t = _ler(a)
        m = re.search(r"""path\(\s*["']admin/["']\s*,\s*admin\.site\.urls""", t)
        if m:
            self.add("Admin do Django no endereço padrão admin/", BAIXO, "ARGOS-ADMIN-PADRAO",
                     _rel(self.raiz, a), _linha(t, m.start()), "path('admin/', admin.site.urls)",
                     "Trocar o caminho e limitar tentativas de login (django-axes).", lentes=[Lente.BOT])
        for m in re.finditer(r"permission_classes\s*=\s*[\[(][^\])]*AllowAny", t):
            self.add("View com AllowAny: confirme que é pública de propósito", BAIXO, "CWE-862",
                     _rel(self.raiz, a), _linha(t, m.start()), "permission_classes = [AllowAny]",
                     "Se não for um endpoint público (login, cadastro), exigir autenticação.")

    # ---- Angular
    def _angular_json(self, a):
        try:
            dados = json.loads(_ler(a))
        except json.JSONDecodeError:
            return
        for nome, proj in (dados.get("projects") or {}).items():
            build = ((proj.get("architect") or proj.get("targets") or {}).get("build") or {})
            prod = (build.get("configurations") or {}).get("production") or {}
            sm = prod.get("sourceMap")
            if sm is True or (isinstance(sm, dict) and sm.get("scripts")):
                self.add(f"Source map ligado no build de produção ({nome})", BAIXO, "CWE-540",
                         _rel(self.raiz, a), 0, "configurations.production.sourceMap = true",
                         "Desligar source map em produção.", tipo=FixTipo.DETERMINISTICO,
                         patch='"sourceMap": false')

    def _angular_env(self, a):
        t = _ler(a)
        for m in re.finditer(r"""(?i)\b(\w*?(?:api_?key|api_?secret|client_?secret|secret|password|senha|token|private_?key))["']?\s*:\s*["']([^"']{8,})["']""", t):
            valor = m.group(2)
            if valor.startswith("AIza"):
                self.add("Chave do Firebase no environment (pública por design)", INFO, "CWE-798",
                         _rel(self.raiz, a), _linha(t, m.start()), f"{m.group(1)}: '{valor[:4]}***'",
                         "Normal no Firebase: a proteção são as regras do Firestore/Storage e as restrições da chave.")
                continue
            self.add("Segredo no environment do Angular: vai pro navegador de todo mundo", ALTO, "CWE-798",
                     _rel(self.raiz, a), _linha(t, m.start()),
                     f"{m.group(1)}: '{valor[:4]}***' fica dentro do JavaScript publicado",
                     "Tudo no front é público. Mover a chamada que usa esse segredo pro backend (DRF) "
                     "e TROCAR a chave.")


class ConfigAdapter(Adapter):
    nome = "config"

    def disponivel(self) -> bool:
        return True

    def escanear(self, ctx: Contexto) -> list[Finding]:
        if not ctx.projeto or not os.path.isdir(ctx.projeto):
            return []
        return Checagem(ctx.projeto).rodar()
