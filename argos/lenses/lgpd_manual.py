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
    "Confirmacao manual: o Argos nao verifica estes itens sozinho "
    "e nao substitui orientacao juridica."
)

CHECKLIST_LGPD: list[tuple[str, str]] = [
    ("Base legal",
     "Cada dado pessoal coletado tem base legal definida (ex.: consentimento) - art. 7."),
    ("Minimizacao",
     "So coleta o necessario pra finalidade (principio da necessidade) - art. 6, III."),
    ("Direitos do titular",
     "Existe canal pro titular pedir acesso, correcao e eliminacao dos dados - art. 18."),
    ("Retencao",
     "Prazo de guarda definido, com eliminacao ou anonimizacao ao fim - arts. 15 e 16."),
    ("Seguranca desde a concepcao",
     "Medidas tecnicas e administrativas pensadas desde o design - art. 46, par. 2."),
    ("Plano de incidente",
     "Roteiro pra comunicar ANPD e titulares em ate 3 dias uteis - art. 48 + Res. CD/ANPD 15/2024."),
    ("Logs limpos",
     "Logs e mensagens de erro nao expoem CPF, e-mail, senha ou token."),
]
