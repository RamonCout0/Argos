"""
Argos — adapter do gitleaks (Fase 1).

gitleaks varre o código atrás de segredos vazados (chaves de API, tokens,
senhas hardcoded). É o primeiro olho do Argos: fácil de rodar, agnóstico
de linguagem (é regex em texto), e muito satisfatório de ver funcionando.

Escrevemos o relatório JSON num arquivo temporário e traduzimos cada
achado num Finding. O segredo em si é SEMPRE mascarado — um tool de
segurança não cospe o segredo de volta.

Robustez de versão: o gitseaks mudou de comando ao longo do tempo. As
versões novas usam `gitleaks dir <pasta>`; as antigas, `gitleaks detect
--source <pasta> --no-git`. Detectamos qual existe e usamos o certo.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

from .base import Adapter, Contexto, caminho_relativo, achar_programa
from ..core import progresso
from ..schema import Finding, Severidade, Lente, Fix, FixTipo


def _mascarar(segredo: str) -> str:
    s = segredo or ""
    if not s:
        return "(oculto)"
    if len(s) <= 8:
        return s[:2] + "***"
    return f"{s[:4]}***{s[-2:]}"


# o gitleaks descreve em ingles e por extenso; aqui vira um titulo curto em portugues
_TITULOS = {
    "generic-api-key": "Chave de API escrita no código",
    "aws-access-token": "Chave da AWS escrita no código",
    "github-pat": "Token do GitHub escrito no código",
    "github-fine-grained-pat": "Token do GitHub escrito no código",
    "gitlab-pat": "Token do GitLab escrito no código",
    "private-key": "Chave privada dentro do projeto",
    "jwt": "Token JWT escrito no código",
    "slack-bot-token": "Token do Slack escrito no código",
    "slack-webhook-url": "Webhook do Slack escrito no código",
    "discord-api-token": "Token do Discord escrito no código",
    "discord-client-secret": "Segredo do Discord escrito no código",
    "stripe-access-token": "Chave do Stripe escrita no código",
    "gcp-api-key": "Chave do Google Cloud escrita no código",
    "openai-api-key": "Chave da OpenAI escrita no código",
    "anthropic-api-key": "Chave da Anthropic escrita no código",
    "telegram-bot-api-token": "Token de bot do Telegram escrito no código",
}


def _titulo(regra: str) -> str:
    if regra in _TITULOS:
        return _TITULOS[regra]
    legivel = regra.replace("-", " ").replace("_", " ").strip() or "segredo"
    return f"Segredo escrito no código ({legivel})"


def parse_relatorio(dados: list[dict], raiz: str | None = None, historico: bool = False) -> list[Finding]:
    """json do gitleaks -> lista de Findings. Função pura (testável sem gitleaks)."""
    findings: list[Finding] = []
    for i, item in enumerate(dados, start=1):
        arquivo = caminho_relativo(item.get("File", "?"), raiz)
        linha = item.get("StartLine", item.get("Line", "?"))
        regra = item.get("RuleID") or item.get("Rule") or "segredo"
        desc = _titulo(regra)
        segredo = item.get("Secret", "")
        commit = (item.get("Commit") or "")[:7]
        if historico:
            desc += " (no histórico do git)"
        findings.append(
            Finding(
                id=f"SECRET-{i:03d}",
                titulo=desc,
                severidade=Severidade.CRITICO,
                categoria="CWE-798",
                origem="gitleaks",
                local=f"{arquivo}:{linha}",
                evidencia=f"{regra}: {_mascarar(segredo)}" + (f" · commit {commit}" if historico and commit else ""),
                lentes=[Lente.CRITICO, Lente.LGPD],
                fix=Fix(
                    FixTipo.IA,
                    "TROCAR a chave no serviço: ela continua no histórico do git, mesmo que o "
                    "arquivo já tenha mudado. Limpar o histórico (git filter-repo) só ajuda se "
                    "ninguém clonou ainda." if historico else
                    "Remover o segredo do codigo e mover pra variavel de ambiente "
                    "(.env, fora do git). Rotacionar a chave, pois ja foi exposta.",
                    None if historico else "chave = os.getenv('NOME_DA_CHAVE')",
                ),
                verificacao="re-rodar gitleaks -> 0 ocorrencias nesse arquivo",
            )
        )
    return findings


def _achar_gitleaks() -> str | None:
    return achar_programa("gitleaks")


class GitleaksAdapter(Adapter):
    nome = "gitleaks"

    def disponivel(self) -> bool:
        return _achar_gitleaks() is not None

    def como_instalar(self) -> str:
        return (
            "Instale o gitleaks: winget install gitleaks  (ou choco install gitleaks, "
            "brew install gitleaks, ou baixe de github.com/gitleaks/gitleaks/releases)."
        )

    def _suporta_dir(self) -> bool:
        """Versões novas do gitleaks têm o subcomando `dir`. As antigas, não."""
        try:
            p = subprocess.run(
                [_achar_gitleaks() or "gitleaks", "dir", "--help"], capture_output=True, text=True
            )
            return p.returncode == 0
        except Exception:
            return False

    def _montar_comando(self, projeto: str, relatorio: str) -> list[str]:
        if self._suporta_dir():
            return [
                _achar_gitleaks() or "gitleaks", "dir", projeto,
                "--report-format", "json",
                "--report-path", relatorio,
            ]
        return [
            _achar_gitleaks() or "gitleaks", "detect",
            "--source", projeto,
            "--no-git",
            "--report-format", "json",
            "--report-path", relatorio,
        ]

    def _comando_historico(self, projeto: str, relatorio: str) -> list[str]:
        exe = _achar_gitleaks() or "gitleaks"
        if self._suporta_dir():  # versões novas: subcomando "git"
            return [exe, "git", projeto, "--report-format", "json", "--report-path", relatorio]
        return [exe, "detect", "--source", projeto, "--report-format", "json", "--report-path", relatorio]

    def _rodar(self, cmd: list[str], relatorio: str) -> list[dict]:
        proc = progresso.rodar(cmd)
        # gitleaks: 0 = limpo, 1 = achou vazamento. Ambos sao "rodou ok".
        if proc.returncode not in (0, 1):
            raise RuntimeError(
                f"gitleaks falhou (codigo {proc.returncode}) com o comando "
                f"{' '.join(cmd[:3])}. stderr: {proc.stderr.strip()[:300]}"
            )
        if not os.path.exists(relatorio):
            return []
        with open(relatorio, encoding="utf-8") as fp:
            conteudo = fp.read().strip()
        return json.loads(conteudo) if conteudo and conteudo != "null" else []

    def escanear(self, ctx: Contexto) -> list[Finding]:
        if not self.disponivel():
            raise FileNotFoundError("gitleaks nao encontrado no PATH. " + self.como_instalar())
        raiz = os.path.abspath(ctx.projeto)
        with tempfile.TemporaryDirectory() as tmp:
            agora = os.path.join(tmp, "gitleaks.json")
            achados = parse_relatorio(self._rodar(self._montar_comando(ctx.projeto, agora), agora), raiz=raiz)
            if not os.path.isdir(os.path.join(raiz, ".git")) or ctx.opcoes.get("sem_historico"):
                return achados
            progresso.avisar("gitleaks: olhando o histórico do git (segredos apagados continuam lá)…", "info")
            hist = os.path.join(tmp, "gitleaks-hist.json")
            try:
                dados = self._rodar(self._comando_historico(ctx.projeto, hist), hist)
            except RuntimeError as e:
                progresso.avisar(f"gitleaks: não consegui ler o histórico ({str(e)[:120]})", "pulado")
                return achados
            vistos = {(f.local, f.evidencia.split(" · ")[0]) for f in achados}
            antigos = [f for f in parse_relatorio(dados, raiz=raiz, historico=True)
                       if (f.local, f.evidencia.split(" · ")[0]) not in vistos]
            # o mesmo segredo em vários commits vira um achado só
            unicos = {}
            for f in antigos:
                unicos.setdefault(f.evidencia.split(" · ")[0], f)
            for i, f in enumerate(unicos.values(), start=len(achados) + 1):
                f.id = f"SECRET-{i:03d}"
            return achados + list(unicos.values())
