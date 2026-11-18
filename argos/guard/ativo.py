"""
Argos — a trava do MODO ATAQUE (Fase 7).

O modo ataque manda requisição de verdade, cria e apaga dados e martela o
servidor até ele cair. Por isso ele só roda se as DUAS condições valerem, e
não existe opção, variável ou flag pra pular nenhuma delas:

  1. SÓ REPOSITÓRIO DO DONO: a pasta é um repositório git cujo `origin` está
     no GitHub, e o GitHub confirma que quem está rodando é ADMINISTRADOR
     dele (pelo `gh` logado ou por GITHUB_TOKEN). Clonou o projeto de outra
     pessoa? Não ataca.
  2. SÓ LOCALHOST, SÓ O PROCESSO DO ARGOS: o alvo não é uma URL escolhida
     por alguém. O próprio Argos sobe o app da pasta em 127.0.0.1, numa porta
     livre, e só ataca esse processo. Nem um túnel (ssh -L) apontando
     localhost pra um site real passa, porque o Argos nunca se conecta a um
     servidor que ele mesmo não iniciou.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import urllib.request
from urllib.parse import urlsplit


class AtaqueRecusado(Exception):
    """O modo ataque não roda aqui. A mensagem diz por quê e o que fazer."""


_GITHUB = re.compile(r"github\.com[:/]+([^/\s]+)/([^/\s]+?)(?:\.git)?/?$", re.I)


def repositorio_github(pasta: str) -> tuple[str, str]:
    """(dono, repositório) do `origin` da pasta. Recusa se não for git/GitHub."""
    if not os.path.isdir(os.path.join(pasta, ".git")):
        raise AtaqueRecusado(f"{pasta} não é a raiz de um repositório git. O modo ataque só roda "
                             "em projeto versionado no GitHub, no qual você tem acesso de escrita.")
    git = shutil.which("git")
    if not git:
        raise AtaqueRecusado("git não encontrado: preciso dele pra conferir de quem é o repositório.")
    r = subprocess.run([git, "-C", pasta, "remote", "get-url", "origin"], capture_output=True, text=True)
    url = (r.stdout or "").strip()
    m = _GITHUB.search(url)
    if r.returncode != 0 or not m:
        raise AtaqueRecusado(f"o origin do repositório não é do GitHub ({url or 'sem origin'}). "
                             "Só consigo confirmar o dono pelo GitHub.")
    return m.group(1), m.group(2)


_ULTIMO_ERRO: list[str] = []

# níveis do GitHub que contam como "colaborador deste projeto": escrita pra cima.
# read/triage/sem-acesso NÃO passam — o estranho continua barrado.
_NIVEIS_ESCRITA = ("admin", "maintain", "push")


def _tem_escrita(perms: dict) -> bool:
    """True se o GitHub diz que você tem push, é mantenedor ou admin do repo."""
    return any(bool(perms.get(n)) for n in _NIVEIS_ESCRITA)


def _permissoes_via_gh(dono: str, repo: str) -> dict | None:
    from ..adapters.base import achar_programa
    gh = achar_programa("gh")  # PATH, e também onde o winget instala (sem precisar reabrir o terminal)
    if not gh:
        _ULTIMO_ERRO.append("o GitHub CLI (gh) não foi encontrado")
        return None
    try:
        r = subprocess.run([gh, "api", f"repos/{dono}/{repo}", "--jq", ".permissions"],
                           capture_output=True, text=True, timeout=30, encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        _ULTIMO_ERRO.append(f"o gh não respondeu ({e})")
        return None
    if r.returncode != 0:
        _ULTIMO_ERRO.append("gh: " + ((r.stderr or r.stdout or "").strip().splitlines() or ["erro"])[-1][:160])
        return None
    try:
        return json.loads(r.stdout or "null")
    except ValueError:
        return None


def _permissoes_via_token(dono: str, repo: str) -> dict | None:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        return None
    req = urllib.request.Request(f"https://api.github.com/repos/{dono}/{repo}",
                                 headers={"Authorization": f"Bearer {token}",
                                          "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - API fixa do GitHub
            return (json.loads(resp.read().decode()) or {}).get("permissions")
    except (OSError, ValueError):
        return None


def _execucao_do_actions(dono: str, repo: str) -> dict | None:
    """No GitHub Actions não existe `gh auth login`. A prova é outra: o GitHub confirma, com o token
    que ele mesmo dá SÓ pra esta execução, que a execução existe NESTE repositório. Pra forjar,
    seria preciso uma execução real e um token válido do repositório."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return None
    alvo = f"{dono}/{repo}".lower()
    if (os.environ.get("GITHUB_REPOSITORY") or "").lower() != alvo:
        return {"admin": False}
    token, run = os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_RUN_ID")
    if not token or not run:
        return None
    req = urllib.request.Request(f"https://api.github.com/repos/{dono}/{repo}/actions/runs/{run}",
                                 headers={"Authorization": f"Bearer {token}",
                                          "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - API fixa do GitHub
            dados = json.loads(resp.read().decode()) or {}
    except (OSError, ValueError):
        return None
    nome = ((dados.get("repository") or {}).get("full_name") or "").lower()
    # o workflow só existe porque alguém com escrita no repositório o colocou lá
    return {"admin": nome == alvo and str(dados.get("id")) == str(run), "via": "actions"}


def confirmar_dono(pasta: str, buscar=None) -> str:
    """Devolve 'dono/repo' se o GitHub confirmar que você tem ESCRITA no repositório — colaborador
    de verdade do projeto (push, mantenedor ou admin) — ou que é o CI do próprio repositório,
    provado pela API; senão, recusa."""
    dono, repo = repositorio_github(pasta)
    buscar = buscar or (lambda d, r: _execucao_do_actions(d, r) or _permissoes_via_gh(d, r)
                        or _permissoes_via_token(d, r))
    _ULTIMO_ERRO.clear()
    perms = buscar(dono, repo)
    if perms is None:
        motivo = f" Motivo: {_ULTIMO_ERRO[-1]}." if _ULTIMO_ERRO else ""
        raise AtaqueRecusado(
            f"não consegui perguntar ao GitHub qual é a sua permissão em {dono}/{repo}.{motivo} Instale o "
            "GitHub CLI e faça login (winget install GitHub.cli e depois gh auth login) ou defina GITHUB_TOKEN.")
    if not _tem_escrita(perms):
        raise AtaqueRecusado(f"o GitHub diz que você NÃO tem acesso de escrita em {dono}/{repo}. "
                             "O modo ataque só roda em projeto do qual você é colaborador "
                             "(push, mantenedor ou admin).")
    return f"{dono}/{repo}"


def exigir_loopback(url: str) -> None:
    """Defesa extra: toda requisição do ataque tem que ir pra 127.0.0.1/::1 literal."""
    host = urlsplit(url).hostname or ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise AtaqueRecusado(f"alvo do ataque tem que ser IP de loopback literal, não '{host}'.") from None
    if not ip.is_loopback:
        raise AtaqueRecusado(f"{host} não é loopback. O modo ataque só fala com 127.0.0.1.")
