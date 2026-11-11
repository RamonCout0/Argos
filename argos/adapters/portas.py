"""
Argos — adapter de portas (Fase 5), com psutil.

Pergunta mais importante da trilha nativa: o teu app escuta SÓ na tua máquina
(127.0.0.1) ou na rede toda (0.0.0.0)? O psutil lê isso direto do sistema
operacional, com o processo dono de cada porta. Não manda nenhum pacote.

Escopo obrigatório: --porta e/ou --processo. Sem isso o relatório viraria a
lista de todo serviço do Windows, que não é o teu app.
"""
from __future__ import annotations

import socket

from .base import Adapter, Contexto
from ..schema import Finding, Severidade, Fix, FixTipo
from ..native.riscos import risco_da_porta

_TODAS = {"0.0.0.0", "::", ""}


def _e_loopback(ip: str) -> bool:
    return ip.startswith("127.") or ip in ("::1", "localhost")


def listar_sockets() -> list[dict]:
    """Portas TCP em LISTEN: [{ip, porta, pid, processo}]. Precisa do psutil."""
    import psutil

    saida = []
    for c in psutil.net_connections(kind="tcp"):
        if c.status != psutil.CONN_LISTEN or not c.laddr:
            continue
        nome = ""
        if c.pid:
            try:
                nome = psutil.Process(c.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                nome = "?"
        saida.append({"ip": c.laddr.ip, "porta": c.laddr.port, "pid": c.pid, "processo": nome})
    return saida


def classificar(sockets: list[dict], portas=None, processo=None) -> list[Finding]:
    """Função pura: sockets -> findings, só dentro do escopo pedido."""
    portas = set(portas or [])
    proc = (processo or "").lower()

    def no_escopo(s):
        return (s["porta"] in portas) or (proc and proc in (s.get("processo") or "").lower())

    por_porta: dict[int, list[dict]] = {}
    for s in sockets:
        if no_escopo(s):
            por_porta.setdefault(s["porta"], []).append(s)

    findings: list[Finding] = []
    n = 0
    for porta in sorted(por_porta):
        grupo = por_porta[porta]
        binds = sorted({s["ip"] or "0.0.0.0" for s in grupo})
        donos = sorted({f"{s.get('processo') or '?'} (pid {s.get('pid')})" for s in grupo})
        exposta = any(ip in _TODAS or not _e_loopback(ip) for ip in binds)
        n += 1
        evid = f"{', '.join(donos)} escutando em {', '.join(binds)}"
        if exposta:
            sev, cwe, rotulo = risco_da_porta(porta)
            findings.append(Finding(
                id=f"NAT-{n:03d}",
                titulo=f"Porta {porta} ({rotulo}) aberta pra rede toda, nao so pra tua maquina",
                severidade=sev,
                categoria=cwe,
                origem="portas",
                local=f"porta {porta}/tcp",
                evidencia=evid,
                fix=Fix(FixTipo.IA,
                        "Fazer o servico escutar so em 127.0.0.1 no dev (ex.: 'manage.py runserver "
                        "127.0.0.1:8000'; Postgres listen_addresses='localhost'; Redis bind 127.0.0.1; "
                        "Ollama OLLAMA_HOST=127.0.0.1)."),
                verificacao=f"re-rodar 'python cli.py nativo --porta {porta}' -> so 127.0.0.1",
            ))
        else:
            findings.append(Finding(
                id=f"NAT-{n:03d}",
                titulo=f"Porta {porta} escuta so na tua maquina (ok)",
                severidade=Severidade.INFO,
                categoria="INVENTARIO",
                origem="portas",
                local=f"porta {porta}/tcp",
                evidencia=evid,
            ))

    for porta in sorted(portas - set(por_porta)):
        n += 1
        findings.append(Finding(
            id=f"NAT-{n:03d}",
            titulo=f"Nada escutando na porta {porta} (o app esta rodando?)",
            severidade=Severidade.INFO,
            categoria="INVENTARIO",
            origem="portas",
            local=f"porta {porta}/tcp",
        ))
    return findings


class PortasAdapter(Adapter):
    nome = "portas"

    def disponivel(self) -> bool:
        try:
            import psutil  # noqa: F401
            return True
        except ImportError:
            return False

    def como_instalar(self) -> str:
        return "Instale: pip install psutil"

    def escanear(self, ctx: Contexto) -> list[Finding]:
        portas = ctx.opcoes.get("portas") or []
        processo = ctx.opcoes.get("processo")
        if not portas and not processo:
            raise ValueError("defina o escopo com --porta e/ou --processo")
        return classificar(listar_sockets(), portas, processo)


def ip_da_rede() -> str | None:
    """IP desta maquina na rede local. Nao envia pacote (UDP connect so consulta a rota)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()
