"""
Argos — adapter do semgrep (Fase 2), com ponte WSL.

Semgrep é o SAST poliglota: regras pra dezenas de linguagens e frameworks
(Django, Flask, Express, Spring...). É ele que dá alcance ao Argos além do
Python.

No Windows, semgrep é chato de rodar nativo, então usamos o WSL. O adapter
se vira sozinho:
  - se houver `semgrep` nativo no PATH (ex.: rodando dentro do WSL/Linux), usa direto;
  - senão, no Windows, chama `wsl semgrep ...`, convertendo o caminho
    C:\\... -> /mnt/c/... na ida e de volta na exibição.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from .base import Adapter, Contexto, achar_executavel, caminho_relativo
from ..core import progresso
from ..schema import Finding, Severidade, Lente, Fix, FixTipo

_SEV = {
    "ERROR": Severidade.ALTO,
    "WARNING": Severidade.MEDIO,
    "INFO": Severidade.BAIXO,
}


def _win_para_wsl(caminho: str) -> str:
    """C:\\Users\\x\\p -> /mnt/c/Users/x/p. Caminho relativo passa só trocando a barra."""
    c = caminho.replace("\\", "/")
    m = re.match(r"^([a-zA-Z]):/(.*)$", c)
    if m:
        return f"/mnt/{m.group(1).lower()}/{m.group(2)}"
    return c


def _wsl_para_win(caminho: str) -> str:
    """/mnt/c/Users/x -> C:\\Users\\x. Caminho sem /mnt/ volta igual."""
    m = re.match(r"^/mnt/([a-zA-Z])/(.*)$", caminho)
    if m:
        return f"{m.group(1).upper()}:\\" + m.group(2).replace("/", "\\")
    return caminho


# frameworks com regras próprias no semgrep: segmento do check_id -> dependência que ele exige.
# Regra de framework que o projeto NÃO usa é ruído (ex.: regra de SQLAlchemy num projeto Django).
_FRAMEWORK_DEP = {
    "sqlalchemy": "sqlalchemy", "flask": "flask", "fastapi": "fastapi", "pyramid": "pyramid",
    "tornado": "tornado", "aiohttp": "aiohttp", "boto3": "boto3", "pymongo": "pymongo",
    "jinja2": "jinja2", "mako": "mako", "lxml": "lxml", "paramiko": "paramiko", "celery": "celery",
    "django": "django", "express": "express", "react": "react", "angular": "@angular/core",
    "vue": "vue", "nextjs": "next", "jquery": "jquery", "sequelize": "sequelize",
    "mongoose": "mongoose", "knex": "knex", "aws-lambda": "aws-lambda", "puppeteer": "puppeteer",
}
_TOKEN = re.compile(r"[A-Za-z0-9_.@/-]+")


def dependencias_do_projeto(raiz: str) -> set[str]:
    """Nomes de dependência (minúsculos) de requirements*, pyproject, Pipfile e package.json."""
    nomes: set[str] = set()
    for pasta, dirs, arquivos in os.walk(raiz):
        dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "venv", ".venv", "dist", "build"}
                   and not d.startswith(".")]
        for nome in arquivos:
            caminho = os.path.join(pasta, nome)
            if nome == "package.json":
                try:
                    with open(caminho, encoding="utf-8") as fp:
                        dados = json.load(fp)
                    for chave in ("dependencies", "devDependencies", "peerDependencies"):
                        nomes.update(k.lower() for k in (dados.get(chave) or {}))
                except (OSError, ValueError):
                    pass
            elif (nome.startswith("requirements") and nome.endswith(".txt")) or nome in ("pyproject.toml", "Pipfile", "setup.cfg"):
                try:
                    with open(caminho, encoding="utf-8", errors="replace") as fp:
                        for linha in fp:
                            linha = linha.split("#")[0].strip()
                            m = re.match(r'^["\']?([A-Za-z0-9_.-]+)', linha)
                            if m:
                                nomes.add(m.group(1).lower().replace("_", "-"))
                except OSError:
                    pass
        if pasta.count(os.sep) - raiz.count(os.sep) >= 3:
            dirs[:] = []
    return nomes


def _framework_ausente(check_id: str, deps: set[str] | None) -> bool:
    if not deps:
        return False
    for seg in check_id.lower().split("."):
        dep = _FRAMEWORK_DEP.get(seg)
        if dep and dep not in deps:
            return True
    return False


_ORDEM_SEV = [Severidade.CRITICO, Severidade.ALTO, Severidade.MEDIO, Severidade.BAIXO, Severidade.INFO]


def _mais_leve(a: Severidade, b: Severidade) -> Severidade:
    return a if _ORDEM_SEV.index(a) > _ORDEM_SEV.index(b) else b


def _gravidade(extra: dict) -> tuple[Severidade, bool]:
    """(gravidade, é_pra_revisar). Regra de 'auditoria' ou de baixa confiança aponta um lugar
    pra olhar, não uma brecha confirmada: fica no máximo BAIXO; as duas juntas viram INFO."""
    meta = extra.get("metadata") or {}
    sev = _SEV.get((extra.get("severity") or "").upper(), Severidade.MEDIO)
    sub = meta.get("subcategory") or []
    if isinstance(sub, str):
        sub = [sub]
    sub = {x.lower() for x in sub}
    confianca = str(meta.get("confidence") or "").upper()
    auditoria = "audit" in sub or "guardrail" in sub
    baixa = confianca == "LOW"
    if auditoria and baixa:
        return Severidade.INFO, True
    if auditoria or baixa:
        return _mais_leve(sev, Severidade.BAIXO), True
    return sev, False


def parse_relatorio(dados: dict, traduzir=None, raiz=None, deps: set[str] | None = None) -> list[Finding]:
    """json do semgrep -> lista de Findings. Função pura (testável sem a ferramenta)."""
    traduzir = traduzir or (lambda p: p)
    findings: list[Finding] = []
    for r in dados.get("results", []):
        extra = r.get("extra", {}) or {}
        check_id = r.get("check_id", "semgrep")
        if _framework_ausente(check_id, deps):
            continue
        sev, revisar = _gravidade(extra)
        meta = extra.get("metadata", {}) or {}
        cwe = meta.get("cwe") or []
        if isinstance(cwe, str):
            cwe = [cwe]
        categoria = cwe[0].split(":")[0].strip() if cwe else check_id.split(".")[-1]
        msg = (extra.get("message") or check_id or "Problema de codigo").strip()
        caminho = caminho_relativo(traduzir(r.get("path", "?")), raiz)
        linha = (r.get("start") or {}).get("line", "?")
        titulo = msg.split("\n")[0][:110] + (" (revisar)" if revisar else "")
        findings.append(
            Finding(
                id=f"CODE-S{len(findings) + 1:03d}",
                titulo=titulo,
                severidade=sev,
                categoria=categoria,
                origem="semgrep",
                local=f"{caminho}:{linha}",
                evidencia=check_id[:120],
                lentes=[Lente.CRITICO],
                fix=Fix(FixTipo.IA, "Conferir se o trecho é mesmo inseguro; se for, aplicar a correção "
                                    "que a regra do Semgrep aponta." if revisar else
                        "Aplicar a correcao que a regra do Semgrep aponta."),
                verificacao=f"re-rodar semgrep -> regra {check_id.split('.')[-1]} limpa",
            )
        )
    return findings


def regras_do_projeto(raiz: str, deps: set[str]) -> list[str]:
    """Conjuntos de regras só da stack do projeto (o p/default traz regra de tudo)."""
    regras: list[str] = []
    tem_py = any(os.path.exists(os.path.join(raiz, n)) for n in ("manage.py", "requirements.txt", "pyproject.toml",
                                                                  "Pipfile", "setup.py")) or \
        any(d in deps for d in ("django", "flask", "fastapi"))
    tem_js = bool(_achar(raiz, "package.json"))
    if tem_py:
        regras.append("p/python")
    if "django" in deps or os.path.exists(os.path.join(raiz, "manage.py")):
        regras.append("p/django")
    if "flask" in deps:
        regras.append("p/flask")
    if tem_js:
        regras += ["p/javascript", "p/typescript"]
    if "react" in deps:
        regras.append("p/react")
    if "express" in deps:
        regras.append("p/express")
    return regras or ["p/default"]


def _achar(raiz: str, nome: str, profundidade: int = 3) -> str | None:
    for pasta, dirs, arquivos in os.walk(raiz):
        dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "venv", ".venv", "dist", "build"}
                   and not d.startswith(".")]
        if nome in arquivos:
            return os.path.join(pasta, nome)
        if pasta.count(os.sep) - raiz.count(os.sep) >= profundidade:
            dirs[:] = []
    return None


# fica fora do SAST: código gerado (cópia do fonte) e testes (inseguro de propósito)
EXCLUIR = ["node_modules", "dist", "build", "frontend_build", "staticfiles", ".angular", "coverage",
           "venv", ".venv", "migrations", "*.min.js", "*.bundle.js", "*.map",
           "tests", "test", "__tests__", "tests.py", "test_*.py", "*_test.py", "conftest.py",
           "*.spec.ts", "*.spec.js", "*.test.ts", "*.test.js", "e2e", "cypress"]


def mensagem_de_erro(proc) -> str:
    """O semgrep às vezes falha com stderr vazio; o motivo fica no JSON de saída ou no traceback."""
    bruto = ((proc.stderr or "") + "\n" + (proc.stdout or "")).strip()
    if "semgrep.dev" in bruto and re.search(r"ProxyError|ConnectionError|Max retries|NameResolution|"
                                            r"timed out|SSLError|403 Forbidden", bruto):
        return ("sem acesso a semgrep.dev pra baixar as regras (precisa de internet; confira a "
                "conexão, o proxy ou o firewall)")
    try:
        dados = json.loads((proc.stdout or "").strip() or "{}")
        erros = [e.get("message") or e.get("long_msg") or e.get("type") for e in dados.get("errors") or []]
        erros = [str(e).strip() for e in erros if e]
        if erros:
            return erros[0][:300]
    except ValueError:
        pass
    linhas = [l.strip() for l in bruto.splitlines() if l.strip()]
    return (linhas[-1][:300] if linhas else "sem mensagem (rode o semgrep sozinho pra ver o motivo)")


class SemgrepAdapter(Adapter):
    nome = "semgrep"

    def __init__(self) -> None:
        self._modo: str | None = None  # "native" | "wsl" | None
        self._exe: str | None = None   # caminho do semgrep nativo
        self._detectado = False

    def _detectar(self) -> None:
        if self._detectado:
            return
        self._detectado = True
        self._exe = achar_executavel("semgrep")
        if self._exe:
            self._modo = "native"
            return
        if os.name == "nt" and shutil.which("wsl"):
            try:
                p = subprocess.run(["wsl", "semgrep", "--version"], capture_output=True, text=True)
                if p.returncode == 0:
                    self._modo = "wsl"
                    return
            except Exception:
                pass
        self._modo = None

    def disponivel(self) -> bool:
        self._detectar()
        return self._modo is not None

    def como_instalar(self) -> str:
        if os.name != "nt":
            return "Instale: pip install semgrep"
        return (
            "Instale o semgrep no WSL (Ubuntu): sudo python3 -m venv /opt/semgrep && "
            "sudo /opt/semgrep/bin/pip install semgrep && "
            "sudo ln -sf /opt/semgrep/bin/semgrep /usr/local/bin/semgrep"
        )

    def escanear(self, ctx: Contexto) -> list[Finding]:
        self._detectar()
        if self._modo is None:
            raise FileNotFoundError(
                "semgrep nao encontrado (nem nativo, nem via WSL). " + self.como_instalar()
            )

        # "--config auto" exige telemetria ligada; com --metrics=off escolhemos as regras pela
        # stack do projeto (precisa de internet pra baixar). Segredos ficam com o gitleaks.
        raiz = os.path.abspath(ctx.projeto)
        deps = dependencias_do_projeto(raiz)
        regras = []
        for r in regras_do_projeto(raiz, deps):
            regras += ["--config", r]
        progresso.avisar("semgrep: regras " + ", ".join(regras[1::2]), "info")
        excluir = []
        for e in EXCLUIR:
            excluir += ["--exclude", e]
        base = ["semgrep", "scan", *regras, *excluir, "--json", "--metrics=off"]
        if self._modo == "wsl":
            alvo = _win_para_wsl(os.path.abspath(ctx.projeto))
            cmd = ["wsl"] + base + [alvo]
            traduzir = _wsl_para_win
        else:
            cmd = [self._exe or "semgrep"] + base[1:] + [ctx.projeto]
            traduzir = None

        proc = progresso.rodar(cmd)
        # semgrep: 0 = ok, 1 = achou algo. >=2 = erro de verdade.
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"semgrep falhou (codigo {proc.returncode}): {mensagem_de_erro(proc)}")
        saida = proc.stdout.strip()
        if not saida:
            return []
        return parse_relatorio(json.loads(saida), traduzir=traduzir, raiz=raiz, deps=deps)
