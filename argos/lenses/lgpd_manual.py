"""
Argos — checklist manual da LGPD (Fase 3).

A LGPD tem uma parte técnica (que os scanners pegam: dado exposto, em texto
claro, em log, cripto fraca) e uma parte de processo/jurídica que nenhum
scanner verifica sozinho. Essa segunda parte aparece aqui como itens de
CONFIRMAÇÃO MANUAL na lente LGPD — fora do score, pra não fingir que é
automática.

Referências: Lei 13.709/2018 (LGPD) e Resolução CD/ANPD nº 15/2024.
"""
from __future__ import annotations

AVISO = (
    "Confirmação manual: o Argos não verifica estes itens sozinho "
    "e não substitui orientação jurídica."
)

CHECKLIST_LGPD: list[tuple[str, str]] = [
    ("Base legal",
     "Cada dado pessoal coletado tem base legal definida (ex.: consentimento) — art. 7º."),
    ("Minimização",
     "Só coleta o necessário pra finalidade (princípio da necessidade) — art. 6º, III."),
    ("Direitos do titular",
     "Existe canal pro titular pedir acesso, correção e eliminação dos dados — art. 18."),
    ("Retenção",
     "Prazo de guarda definido, com eliminação ou anonimização ao fim — arts. 15 e 16."),
    ("Segurança desde a concepção",
     "Medidas técnicas e administrativas pensadas desde o design — art. 46, § 2º."),
    ("Plano de incidente",
     "Roteiro pra comunicar ANPD e titulares em até 3 dias úteis — art. 48 + Res. CD/ANPD 15/2024."),
    ("Logs limpos",
     "Logs e mensagens de erro não expõem CPF, e-mail, senha ou token."),
]
