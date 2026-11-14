"""
Argos — dependências vulneráveis de TODAS as linguagens (v2.2).

O pip-audit só enxerga Python. Num projeto Django + Angular, a maior parte
das bibliotecas está no package-lock.json do front. Aqui:

  - OSV-Scanner (Google): lê os arquivos de dependência de várias linguagens
    de uma vez (package-lock, yarn.lock, pnpm-lock, requirements, poetry.lock,
    Pipfile.lock, go.mod, Cargo.lock, composer.lock...) e consulta a base
    pública osv.dev. Precisa de internet.
  - npm audit: reserva pro front quando o OSV-Scanner não está instalado.
    Se o OSV estiver, o npm audit não roda (seria a mesma coisa duas vezes).

A categoria de cada achado prefere o CVE (igual ao pip-audit), pra que a
mesma falha achada pelos dois scanners vire um achado só.
"""
from __future__ import annotations

import json
import os
import re

from .base import Adapter, Contexto, achar_programa, caminho_relativo
from ..core import progresso
from ..schema import Finding, Severidade, Lente, Fix, FixTipo

_SEV_TEXTO = {"CRITICAL": Severidade.CRITICO, "HIGH": Severidade.ALTO, "MODERATE": Severidade.MEDIO,
              "MEDIUM": Severidade.MEDIO, "LOW": Severidade.BAIXO}
IGNORAR_PASTAS = {"node_modules", ".git", "venv", ".venv", "env", "dist", "build", ".angular", "__pycache__"}


def _sev_cvss(valor) -> Severidade | None:
    try:
        n = float(valor)
    except (TypeError, ValueError):
        return None
    if n >= 9:
        return Severidade.CRITICO
    if n >= 7:
        return Severidade.ALTO
    if n >= 4:
        return Severidade.MEDIO
    return Severidade.BAIXO


def _categoria(ids: list[str]) -> str:
    """CVE primeiro (casa com o pip-audit), depois GHSA, depois o que vier."""
    for prefixo in ("CVE-", "GHSA-"):
        for i in ids:
            if i.startswith(prefixo):
                return i
    return ids[0] if ids else "DEP-VULN"


def _versao_corrigida(vuln: dict, pacote: str) -> str | None:
    for afetado in vuln.get("affected") or []:
        nome = ((afetado.get("package") or {}).get("name") or "").lower()
        if nome and nome != pacote.lower():
            continue
        for faixa in afetado.get("ranges") or []:
            for ev in faixa.get("events") or []:
                if ev.get("fixed"):
                    return ev["fixed"]
    return None


def parse_osv(dados: dict, raiz: str | None = None) -> list[Finding]:
    """JSON do osv-scanner (v1 ou v2) -> Findings. Um achado por grupo de aliases."""
    achados: list[Finding] = []
    for res in dados.get("results") or []:
        fonte = caminho_relativo((res.get("source") or {}).get("path", "?"), raiz)
        for pkg in res.get("packages") or []:
            info = pkg.get("package") or {}
            nome, versao = info.get("name", "?"), info.get("version", "?")
            eco = info.get("ecosystem", "")
            vulns = {v.get("id"): v for v in pkg.get("vulnerabilities") or []}
            grupos = pkg.get("groups") or [{"ids": [i]} for i in vulns]
            for g in grupos:
                ids = [i for i in g.get("ids") or [] if i]
                todos = set(ids)
                for i in ids:
                    todos.update((vulns.get(i) or {}).get("aliases") or [])
                principal = next((vulns[i] for i in ids if i in vulns), {})
                sev = _sev_cvss(g.get("max_severity"))
                if sev is None:
                    texto = ((principal.get("database_specific") or {}).get("severity") or "").upper()
                    sev = _SEV_TEXTO.get(texto, Severidade.ALTO)
                cat = _categoria(sorted(todos))
                corrigida = _versao_corrigida(principal, nome)
                resumo = (principal.get("summary") or principal.get("details") or "").strip().split("\n")[0][:160]
                fix = (Fix(FixTipo.DETERMINISTICO, f"Atualizar {nome} para {corrigida} ou mais nova.",
                           f"{nome}@{corrigida}" if eco == "npm" else f"{nome}=={corrigida}")
                       if corrigida else
                       Fix(FixTipo.IA, f"Ainda não há versão corrigida de {nome}. Avaliar trocar a "
                                       "biblioteca ou mitigar o uso da parte vulnerável."))
                achados.append(Finding(
                    id=f"DEP-O{len(achados) + 1:03d}",
                    titulo=f"{nome} {versao} tem falha conhecida ({cat})",
                    severidade=sev, categoria=cat, origem="osv-scanner",
                    local=f"{fonte}:{nome}", evidencia=resumo or ", ".join(sorted(todos))[:160],
                    lentes=[Lente.CRITICO], fix=fix,
                    verificacao="atualizar e re-rodar o scan -> a falha some"))
    return achados


class OsvAdapter(Adapter):
    nome = "osv-scanner"

    def disponivel(self) -> bool:
        return achar_programa("osv-scanner") is not None

    def como_instalar(self) -> str:
        return ("Instale o OSV-Scanner (dependências de todas as linguagens): winget install Google.OSVScanner  "
                "(ou go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest, ou baixe de "
                "github.com/google/osv-scanner/releases).")

    def _comando(self, exe: str, pasta: str) -> list[str]:
        versao = progresso.rodar([exe, "--version"], timeout=30)
        texto = (versao.stdout or "") + (versao.stderr or "")
        m = re.search(r"(\d+)\.\d+\.\d+", texto)
        if m and int(m.group(1)) >= 2:
            return [exe, "scan", "source", "-r", "--format", "json", pasta]
        return [exe, "--format", "json", "-r", pasta]

    def escanear(self, ctx: Contexto) -> list[Finding]:
        exe = achar_programa("osv-scanner")
        if not exe:
            raise FileNotFoundError("osv-scanner não encontrado. " + self.como_instalar())
        proc = progresso.rodar(self._comando(exe, ctx.projeto), timeout=600)
        # 0 = limpo, 1 = achou falha, 128 = nenhum arquivo de dependência na pasta
        if proc.returncode == 128:
            progresso.avisar("osv-scanner: nenhum arquivo de dependências na pasta", "info")
            return []
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"osv-scanner falhou ({proc.returncode}): {(proc.stderr or '').strip()[:300]}")
        saida = (proc.stdout or "").strip()
        if not saida:
            return []
        return parse_osv(json.loads(saida[saida.find("{"):]), raiz=os.path.abspath(ctx.projeto))


# ------------------------------------------------------------------ npm audit (reserva)

_SEV_NPM = {"critical": Severidade.CRITICO, "high": Severidade.ALTO, "moderate": Severidade.MEDIO,
            "low": Severidade.BAIXO, "info": Severidade.INFO}


def parse_npm(dados: dict, arquivo: str = "package-lock.json") -> list[Finding]:
    """JSON do `npm audit --json` (npm 7+) -> Findings. Um achado por pacote com aviso próprio."""
    achados: list[Finding] = []
    for nome, v in (dados.get("vulnerabilities") or {}).items():
        avisos = [x for x in v.get("via") or [] if isinstance(x, dict)]
        if not avisos:
            continue  # só herdou a falha de outra dependência; o aviso vem no pacote de origem
        ghsa = sorted({m.group(0) for a in avisos for m in [re.search(r"GHSA-[\w-]+", a.get("url") or "")] if m})
        sev = _SEV_NPM.get(v.get("severity", ""), Severidade.ALTO)
        fixa = v.get("fixAvailable")
        if isinstance(fixa, dict):
            alvo = f"{fixa.get('name')}@{fixa.get('version')}"
            aviso = " (muda a versão principal: testar antes)" if fixa.get("isSemVerMajor") else ""
            fix = Fix(FixTipo.DETERMINISTICO, f"Atualizar pra {alvo}{aviso}.", f"npm install {alvo}")
        elif fixa:
            fix = Fix(FixTipo.DETERMINISTICO, "Há correção compatível: rodar npm audit fix.", "npm audit fix")
        else:
            fix = Fix(FixTipo.IA, f"Sem correção publicada pra {nome}. Avaliar trocar a biblioteca.")
        achados.append(Finding(
            id=f"DEP-N{len(achados) + 1:03d}",
            titulo=f"{nome} tem falha conhecida ({ghsa[0] if ghsa else 'npm audit'})",
            severidade=sev, categoria=ghsa[0] if ghsa else "NPM-AUDIT", origem="npm-audit",
            local=f"{arquivo}:{nome}", evidencia=(avisos[0].get("title") or "")[:160] + f" · versões {v.get('range', '?')}",
            lentes=[Lente.CRITICO], fix=fix, verificacao="npm audit -> sem aviso pra esse pacote"))
    return achados


def _locks(raiz: str, limite: int = 8) -> list[str]:
    achados = []
    for pasta, dirs, nomes in os.walk(raiz):
        dirs[:] = [d for d in dirs if d not in IGNORAR_PASTAS and not d.startswith(".")]
        if "package-lock.json" in nomes:
            achados.append(os.path.join(pasta, "package-lock.json"))
            if len(achados) >= limite:
                break
    return achados


class NpmAuditAdapter(Adapter):
    nome = "npm-audit"

    def disponivel(self) -> bool:
        return achar_programa("npm") is not None

    def como_instalar(self) -> str:
        return "Instale o Node.js (vem com o npm) pra auditar o package-lock.json do front."

    def escanear(self, ctx: Contexto) -> list[Finding]:
        if achar_programa("osv-scanner"):
            progresso.avisar("npm-audit: o OSV-Scanner já cobre o npm, pulando", "info")
            return []
        npm = achar_programa("npm")
        raiz = os.path.abspath(ctx.projeto)
        achados: list[Finding] = []
        for lock in _locks(raiz):
            pasta = os.path.dirname(lock)
            rel = caminho_relativo(lock, raiz)
            progresso.avisar(f"npm-audit: {rel}", "info")
            # --omit=dev: o que vai pro navegador/servidor (ferramentas de build ficam de fora)
            proc = progresso.rodar([npm, "audit", "--json", "--omit=dev"], timeout=300, cwd=pasta)
            saida = (proc.stdout or "").strip()
            if not saida.startswith("{"):
                raise RuntimeError(f"npm audit falhou em {rel}: {(proc.stderr or saida).strip()[:200]}")
            dados = json.loads(saida)
            if "error" in dados and not dados.get("vulnerabilities"):
                raise RuntimeError(f"npm audit em {rel}: {str(dados['error'])[:200]}")
            for f in parse_npm(dados, rel):
                f.id = f"DEP-N{len(achados) + 1:03d}"
                achados.append(f)
        return achados
