"""
Argos — adapter do tshark (Fase 5).

O que o teu app MANDA pela rede em HTTP sem TLS? Só olha HTTP em texto puro
(que qualquer um no caminho já consegue ler); tráfego HTTPS não é aberto.

Dois modos:
  - ao vivo: captura N segundos (padrão 30) enquanto você usa o app;
  - --pcap:  analisa uma captura que você já fez no Wireshark.

Privacidade: nada da captura é salvo em disco. Só sai no relatório o que foi
achado, mascarado (CPF vira ***.***.***-25, senha vira "campo senha").
Na captura ao vivo, use SÓ o teu app durante a janela.

Peso:
  - credencial (senha, token, Authorization, cookie de sessão) pra host externo -> CRÍTICO
  - CPF pra host externo -> ALTO; e-mail -> MÉDIO
  - qualquer HTTP sem TLS pra host externo -> MÉDIO
  - pra localhost/rede local -> BAIXO (normal no dev, mas em produção é HTTPS)
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from urllib.parse import urlsplit

from .base import Adapter, Contexto
from ..core import progresso
from ..schema import Finding, Severidade, Fix, FixTipo
from ..native.riscos import ip_e_local
from ..native.sensiveis import detectar

CAMPOS = [
    "ip.dst", "ipv6.dst", "tcp.dstport",
    "http.host", "http.request.method", "http.request.uri",
    "http.authorization", "http.cookie", "http.file_data",
    "urlencoded-form.key", "urlencoded-form.value",
]

_CAMINHOS_WINDOWS = [r"C:\Program Files\Wireshark\tshark.exe"]
_HEX = re.compile(r"^[0-9a-fA-F:]+$")


def _binario() -> str | None:
    achado = shutil.which("tshark")
    if achado:
        return achado
    return next((c for c in _CAMINHOS_WINDOWS if os.path.exists(c)), None)


def _texto_de(valor: str) -> str:
    """Wireshark 4.x as vezes entrega o corpo em hex. Volta pra texto."""
    v = valor or ""
    limpo = v.replace(":", "")
    if len(limpo) >= 8 and len(limpo) % 2 == 0 and _HEX.match(v):
        try:
            return bytes.fromhex(limpo).decode("utf-8", "replace")
        except ValueError:
            return v
    return v


def requisicoes_do_json(dados: list) -> list[dict]:
    """saida 'tshark -T json -e ...' -> lista de requisicoes HTTP."""
    reqs = []
    for pkt in dados or []:
        camadas = (pkt.get("_source") or {}).get("layers") or {}

        def um(campo):
            v = camadas.get(campo) or [""]
            return v[0] if isinstance(v, list) else str(v)

        metodo = um("http.request.method")
        if not metodo:
            continue
        corpo = _texto_de(um("http.file_data"))
        chaves, valores = camadas.get("urlencoded-form.key", []), camadas.get("urlencoded-form.value", [])
        if chaves and not corpo:
            corpo = "&".join(f"{k}={v}" for k, v in zip(chaves, valores))
        destino = um("ip.dst") or um("ipv6.dst")
        reqs.append({
            "ip": destino,
            "porta": um("tcp.dstport"),
            "host": um("http.host") or destino,
            "metodo": metodo,
            "uri": um("http.request.uri") or "/",
            "autorizacao": um("http.authorization"),
            "cookie": um("http.cookie"),
            "corpo": corpo,
        })
    return reqs


def analisar(reqs: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    hosts_vistos: set[str] = set()
    n = 0

    def novo(**kw):
        nonlocal n
        n += 1
        findings.append(Finding(id=f"TRF-{n:03d}", origem="tshark", **kw))

    for r in reqs:
        local = ip_e_local(r["ip"])
        caminho = urlsplit(r["uri"]).path or "/"
        destino = f"{r['metodo']} http://{r['host']}{caminho}"
        achado = detectar(f"{r['uri']}\n{r['corpo']}", r["autorizacao"], r["cookie"])
        nota = " (localhost/rede local: normal no dev, mas em producao precisa ser HTTPS)" if local else ""
        fix_https = Fix(FixTipo.IA, "Usar HTTPS nesse endpoint e nunca mandar credencial/dado pessoal na URL.")

        if achado["credenciais"]:
            novo(titulo=f"Credencial trafegando sem criptografia{nota}",
                 severidade=Severidade.BAIXO if local else Severidade.CRITICO,
                 categoria="CWE-319", local=destino,
                 evidencia="; ".join(achado["credenciais"]), fix=fix_https,
                 verificacao="capturar de novo -> nenhuma credencial em HTTP")
        if achado["pessoais"]:
            tem_cpf = any(p.startswith("CPF") for p in achado["pessoais"])
            sev = Severidade.BAIXO if local else (Severidade.ALTO if tem_cpf else Severidade.MEDIO)
            novo(titulo=f"Dado pessoal trafegando sem criptografia{nota}",
                 severidade=sev, categoria="CWE-359", local=destino,
                 evidencia="; ".join(achado["pessoais"]), fix=fix_https,
                 verificacao="capturar de novo -> nenhum dado pessoal em HTTP")
        if not local and r["host"] not in hosts_vistos:
            hosts_vistos.add(r["host"])
            novo(titulo=f"App falando HTTP sem TLS com {r['host']}",
                 severidade=Severidade.MEDIO, categoria="CWE-319",
                 local=f"http://{r['host']}", evidencia=f"{r['ip']}:{r['porta']}",
                 fix=fix_https, verificacao="capturar de novo -> host so em HTTPS")
    return findings


class TsharkAdapter(Adapter):
    nome = "tshark"

    def disponivel(self) -> bool:
        return _binario() is not None

    def como_instalar(self) -> str:
        return ("Instale o Wireshark (traz o tshark e o Npcap): https://www.wireshark.org/download.html "
                "- marque 'Support loopback traffic' no Npcap pra capturar localhost.")

    def comando(self, opcoes: dict) -> list[str]:
        cmd = [_binario() or "tshark"]
        if opcoes.get("pcap"):
            cmd += ["-r", opcoes["pcap"]]
        else:
            segundos = max(5, min(int(opcoes.get("segundos", 30)), 300))
            portas = opcoes.get("portas_http") or [80, 8080, 8000]
            if opcoes.get("interface"):
                cmd += ["-i", opcoes["interface"]]
            cmd += ["-a", f"duration:{segundos}", "-f", " or ".join(f"tcp port {int(p)}" for p in portas)]
        cmd += ["-Y", "http.request", "-T", "json"]
        for c in CAMPOS:
            cmd += ["-e", c]
        return cmd

    def escanear(self, ctx: Contexto) -> list[Finding]:
        opcoes = ctx.opcoes
        limite = 60 if opcoes.get("pcap") else int(opcoes.get("segundos", 30)) + 60
        proc = progresso.rodar(self.comando(opcoes), timeout=limite)
        if proc.returncode != 0:
            raise RuntimeError(f"tshark falhou ({proc.returncode}): {proc.stderr.strip()[:300]}")
        saida = proc.stdout.strip()
        if not saida:
            return []
        return analisar(requisicoes_do_json(json.loads(saida)))
