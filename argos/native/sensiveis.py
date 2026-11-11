"""
Argos — detector de dado sensível em texto (Fase 5).

Procura credencial e dado pessoal em requisições HTTP sem TLS. Tudo que é
achado sai MASCARADO: o relatório diz "tem CPF aqui", nunca o CPF.
"""
from __future__ import annotations

import re
from urllib.parse import unquote_plus

_CPF = re.compile(r"(?<!\d)(\d{3}\.?\d{3}\.?\d{3}-?\d{2})(?!\d)")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_SENHA = re.compile(r"(?i)(?:^|[?&\s\"{,])(senha|password|passwd|pwd|pass)\"?\s*[=:]\s*\"?([^&\s\"]+)")
_TOKEN = re.compile(r"(?i)(?:^|[?&\s\"{,])(token|access_token|api_key|apikey|secret|client_secret)\"?\s*[=:]\s*\"?([^&\s\"]+)")
_COOKIE_SESSAO = re.compile(r"(?i)\b([\w.-]*(?:sess|token|auth|jwt)[\w.-]*)=")


def cpf_valido(cpf: str) -> bool:
    d = [int(c) for c in re.sub(r"\D", "", cpf)]
    if len(d) != 11 or len(set(d)) == 1:
        return False
    for tam in (9, 10):
        soma = sum(d[i] * (tam + 1 - i) for i in range(tam))
        dig = (soma * 10) % 11 % 10
        if dig != d[tam]:
            return False
    return True


def mascarar_cpf(cpf: str) -> str:
    return "***.***.***-" + re.sub(r"\D", "", cpf)[-2:]


def mascarar_email(email: str) -> str:
    usuario, _, dominio = email.partition("@")
    return f"{usuario[:1]}***@{dominio}"


def detectar(texto: str, autorizacao: str = "", cookie: str = "") -> dict:
    """
    -> {"credenciais": [...], "pessoais": [...]}  (descrições já mascaradas)
    """
    t = unquote_plus(texto or "")
    cred: list[str] = []
    pess: list[str] = []

    if autorizacao:
        esquema = autorizacao.split()[0] if autorizacao.split() else "?"
        cred.append(f"cabecalho Authorization ({esquema} ***)")
    for m in _SENHA.finditer(t):
        cred.append(f"campo '{m.group(1)}' com senha")
    for m in _TOKEN.finditer(t):
        cred.append(f"parametro '{m.group(1)}'")
    for nome in _COOKIE_SESSAO.findall(cookie or ""):
        cred.append(f"cookie de sessao '{nome}=***'")

    for m in _CPF.finditer(t):
        if cpf_valido(m.group(1)):
            pess.append(f"CPF {mascarar_cpf(m.group(1))}")
    for m in _EMAIL.finditer(t):
        pess.append(f"e-mail {mascarar_email(m.group(0))}")

    return {"credenciais": list(dict.fromkeys(cred)), "pessoais": list(dict.fromkeys(pess))}
