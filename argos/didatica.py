"""
Argos — camada didática (Fase D).

Pra cada achado, além do "o que é / como corrigir" (que já vem de ai/templates),
monta o pacote que ensina o iniciante:
  - quão comum é a falha (OWASP Top 10 2021 e/ou CWE Top 25);
  - quão crítica (faixa APROXIMADA de CVSS a partir da severidade — não é um
    vetor CVSS real, é só pra dar noção de grandeza, e isso fica explícito);
  - por que corrigir e como (texto-base);
  - links oficiais pra aprofundar (MITRE CWE e OWASP).

Tudo é fato público (rankings, categorias, URLs) escrito com as nossas palavras.
"""
from __future__ import annotations

import re

from .schema import Finding, Severidade
from .ai.templates import explicacao_base

# faixa aproximada de CVSS por severidade (deixamos claro que é aproximação)
_CVSS = {
    Severidade.CRITICO: ("Crítico", "9.0–10.0"),
    Severidade.ALTO: ("Alto", "7.0–8.9"),
    Severidade.MEDIO: ("Médio", "4.0–6.9"),
    Severidade.BAIXO: ("Baixo", "0.1–3.9"),
    Severidade.INFO: ("Informativo", "—"),
}

# categorias do OWASP Top 10 2021 (rótulo + link oficial)
_OWASP = {
    "A01": ("A01:2021 – Quebra de Controle de Acesso", "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
    "A02": ("A02:2021 – Falhas Criptográficas", "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
    "A03": ("A03:2021 – Injeção", "https://owasp.org/Top10/A03_2021-Injection/"),
    "A04": ("A04:2021 – Design Inseguro", "https://owasp.org/Top10/A04_2021-Insecure_Design/"),
    "A05": ("A05:2021 – Configuração Incorreta de Segurança", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
    "A06": ("A06:2021 – Componentes Vulneráveis e Desatualizados", "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"),
    "A07": ("A07:2021 – Falhas de Identificação e Autenticação", "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"),
    "A09": ("A09:2021 – Falhas de Registro e Monitoramento", "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"),
    "LLM01": ("OWASP LLM Top 10 – LLM01: Prompt Injection", "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"),
}

# CWE -> categoria OWASP
_CWE_OWASP = {
    "CWE-798": "A07", "CWE-259": "A07", "CWE-306": "A07", "CWE-307": "A07",
    "CWE-78": "A03", "CWE-95": "A03", "CWE-89": "A03", "CWE-79": "A03",
    "CWE-327": "A02", "CWE-916": "A02", "CWE-319": "A02", "CWE-614": "A02", "CWE-311": "A02",
    "CWE-532": "A09",
    "CWE-668": "A01", "CWE-862": "A01", "CWE-359": "A01", "CWE-538": "A01",
    "CWE-527": "A01", "CWE-540": "A05", "CWE-548": "A05", "CWE-497": "A01",
    "CWE-489": "A05", "CWE-693": "A05", "CWE-1021": "A05", "CWE-942": "A05",
    "CWE-1004": "A05", "CWE-1275": "A05", "CWE-16": "A05",
    "CWE-1427": "LLM01",
}

# CWE Top 25 (2023) — IDs mais perigosos segundo a MITRE (lista pública)
_TOP25 = {
    "CWE-79", "CWE-787", "CWE-89", "CWE-416", "CWE-78", "CWE-20", "CWE-125", "CWE-22",
    "CWE-352", "CWE-434", "CWE-862", "CWE-476", "CWE-287", "CWE-190", "CWE-502", "CWE-77",
    "CWE-119", "CWE-798", "CWE-918", "CWE-306", "CWE-362", "CWE-269", "CWE-94", "CWE-863", "CWE-276",
}

_NUM = re.compile(r"CWE-(\d+)", re.I)


def _cwe_url(categoria: str) -> str | None:
    m = _NUM.search(categoria or "")
    return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html" if m else None


def _quao_comum(cat: str) -> str:
    owasp = _CWE_OWASP.get(cat)
    top25 = cat in _TOP25
    if owasp and top25:
        return "Muito comum: está no OWASP Top 10 e no CWE Top 25 (as fraquezas mais perigosas e frequentes)."
    if owasp:
        return "Comum: faz parte do OWASP Top 10, a lista das falhas de segurança web mais frequentes."
    if top25:
        return "Comum: está no CWE Top 25 da MITRE, as fraquezas de software mais perigosas."
    return "Aparece com frequência em projetos web, mas fora das listas Top 10 / Top 25."


def para_dict(f: Finding) -> dict:
    cat = (f.categoria or "").upper().strip()
    rotulo, faixa = _CVSS.get(f.severidade, ("—", "—"))
    risco, caminho = explicacao_base(cat)
    links = []
    url = _cwe_url(cat)
    if url:
        links.append({"rot": cat + " (MITRE)", "url": url})
    owasp = _OWASP.get(_CWE_OWASP.get(cat, ""))
    if owasp:
        links.append({"rot": owasp[0], "url": owasp[1]})
    return {
        "cvss_rotulo": rotulo,
        "cvss_faixa": faixa,          # faixa aproximada; o front mostra "(aprox.)"
        "quao_comum": _quao_comum(cat),
        "por_que": f.explicacao or risco,
        "como": caminho,
        "links": links,
    }
