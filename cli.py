"""
Argos — CLI.

Veredito final (Fase 6):
  python cli.py auditar <pasta> [--porta 8000 --rede] [--pcap c.pcap | --capturar 30] --html relatorio.html

Trilhas separadas:
  python cli.py scan <pasta>                 -> o codigo (gitleaks, pip-audit, semgrep)
  python cli.py nativo --porta 8000 [--rede] -> o app rodando: escuta so local ou pra rede?
  python cli.py nativo --listar              -> tudo que esta escutando na maquina
  python cli.py trafego [--segundos 30]      -> dado sensivel em HTTP sem TLS (ao vivo)
  python cli.py trafego --pcap arquivo.pcap  -> analisa uma captura do Wireshark

Opcoes de relatorio (em scan/nativo/trafego/auditar):
  --lente critico|lgpd|bot   --ia   --html arq.html   --saida-json arq.json
  --falhar-em medio|baixo    (selo mais rigoroso; nunca mais frouxo que 'alto')

Riscos aceitos (falso positivo), com motivo e prazo:
  python cli.py aceitar CODE-S002 --motivo "eval so roda em teste" --dias 30
  python cli.py aceitos

Outros:
  python cli.py demo [--html demo.html]      -> relatorio de exemplo (sem scanner)
  python cli.py ia-status                    -> confere o Ollama local
  python cli.py check <alvo>                 -> testa a trava (local ou dono verificado)
  python cli.py segredo | token <host>       -> verificacao de dono pra producao
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys

from argos.schema import Finding, Severidade, Lente, Fix, FixTipo
from argos.report.console import render
from argos.report.html import render_html
from argos.guard.target_lock import autorizar_alvo, AlvoNaoLocal
from argos.guard.verificacao import (
    AlvoNaoVerificado, gerar_segredo, token_da_semana, url_de_verificacao,
)
from argos.config import carregar_segredo
from argos.core.orchestrator import (
    escanear_projeto, escanear_nativo, analisar_trafego, auditar, Resultado,
)
from argos.core import aceitos as mod_aceitos
from argos.adapters.portas import listar_sockets
from argos.adapters.tshark import TsharkAdapter, _binario as tshark_binario
from argos.lenses.mapa import enriquecer
from argos.scorer import calcular
from argos.ai.narrator import narrar
from argos.ai.ollama import Ollama

_LENTES = {l.value: l for l in Lente}
_LIMITES = {"alto": Severidade.ALTO, "medio": Severidade.MEDIO, "baixo": Severidade.BAIXO}
ULTIMO = os.path.join(".argos_cache", "ultimo.json")


def _lente(args):
    return _LENTES[args.lente] if getattr(args, "lente", None) else None


def _limite(args):
    return _LIMITES[getattr(args, "falhar_em", None) or "alto"]


def _findings_demo() -> list[Finding]:
    return [
        Finding(
            id="SECRET-001",
            titulo="Chave de API hardcoded no codigo",
            severidade=Severidade.CRITICO,
            categoria="CWE-798",
            origem="gitleaks",
            local="config/settings.py:42",
            evidencia="API_KEY = 'sk-l***e1'",
            lentes=[Lente.CRITICO, Lente.LGPD],
            fix=Fix(FixTipo.IA, "Mover pra variavel de ambiente (.env).",
                    "API_KEY = os.getenv('API_KEY')"),
            verificacao="re-rodar gitleaks -> 0 ocorrencias",
        ),
        Finding(
            id="CONF-002",
            titulo="DEBUG=True vaza stacktrace em producao",
            severidade=Severidade.ALTO,
            categoria="CWE-489",
            origem="semgrep",
            local="config/settings.py:12",
            evidencia="DEBUG = True",
            lentes=[Lente.CRITICO],
            fix=Fix(FixTipo.IA, "Ler de env, default False.",
                    "DEBUG = os.getenv('DEBUG', 'False') == 'True'"),
            verificacao="re-rodar semgrep -> regra django-debug-true limpa",
        ),
        Finding(
            id="DEP-003",
            titulo="Dependencia 'requests 2.19' com CVE conhecido",
            severidade=Severidade.MEDIO,
            categoria="CVE-2023-32681",
            origem="pip-audit",
            local="requirements.txt:requests",
            lentes=[Lente.CRITICO],
            fix=Fix(FixTipo.DETERMINISTICO, "Subir para requests >= 2.31.0.",
                    "requests==2.31.0"),
            verificacao="re-rodar pip-audit -> sem CVE nessa dependencia",
        ),
        Finding(
            id="NET-004",
            titulo="Login sem rate limit (brute force livre)",
            severidade=Severidade.MEDIO,
            categoria="CWE-307",
            origem="exemplo",
            local="POST /api/login",
            lentes=[Lente.BOT],
            fix=Fix(FixTipo.IA, "Adicionar rate limit por IP no endpoint de login."),
            verificacao="mandar N requests rapidos -> deve bloquear",
        ),
        Finding(
            id="NAT-005",
            titulo="Porta 8000 escuta so na tua maquina (ok)",
            severidade=Severidade.INFO,
            categoria="INVENTARIO",
            origem="portas",
            local="porta 8000/tcp",
            evidencia="python.exe (pid 4242) escutando em 127.0.0.1",
        ),
    ]


# --------------------------------------------------------------- saida comum

def _narrar_com_ia(findings, args) -> None:
    if not getattr(args, "ia", False):
        narrar(findings, None)
        return
    cliente = Ollama()
    ok, msg = cliente.status()
    if not ok:
        print(f"[ia] indisponivel: {msg}")
        print("[ia] seguindo so com as explicacoes base.")
        narrar(findings, None)
        return
    print(f"[ia] {msg} Gerando explicacoes (pode levar um pouco)...")
    est = narrar(findings, cliente, maximo=args.ia_max)
    print(f"[ia] {est.gerados} novas, {est.do_cache} do cache, {est.falhas} falha(s) "
          f"de {est.candidatos} achado(s) que pedem explicacao.")


def _salvar_ultimo(findings) -> None:
    """Guarda ID -> fingerprint da ultima execucao, pro 'aceitar CODE-S002' funcionar."""
    os.makedirs(os.path.dirname(ULTIMO), exist_ok=True)
    dados = {
        "gerado_em": dt.datetime.now().isoformat(timespec="seconds"),
        "findings": [{"id": f.id, "fingerprint": mod_aceitos.fingerprint(f),
                      "titulo": f.titulo, "severidade": f.severidade.value} for f in findings],
    }
    with open(ULTIMO, "w", encoding="utf-8") as fp:
        json.dump(dados, fp, ensure_ascii=False, indent=1)


def _exportar(findings, meta, args, limite) -> None:
    if getattr(args, "html", None):
        with open(args.html, "w", encoding="utf-8") as fp:
            fp.write(render_html(findings, meta, limite))
        print(f"\nrelatorio HTML: {os.path.abspath(args.html)}")
    if getattr(args, "saida_json", None):
        placar = calcular(findings, limite)
        dados = {
            "gerado_em": dt.datetime.now().isoformat(timespec="seconds"),
            "alvo": meta.get("alvo", ""),
            "score": placar.score,
            "aprovado": placar.aprovado,
            "limite": limite.value,
            "rodaram": meta.get("rodaram", []),
            "pulados": [{"scanner": n, "motivo": m} for n, m in meta.get("pulados", [])],
            "avisos": meta.get("avisos", []),
            "findings": [dict(f.to_dict(), fingerprint=mod_aceitos.fingerprint(f)) for f in findings],
        }
        with open(args.saida_json, "w", encoding="utf-8") as fp:
            json.dump(dados, fp, ensure_ascii=False, indent=2)
        print(f"relatorio JSON: {os.path.abspath(args.saida_json)}")


def _finalizar(res: Resultado, args, alvo: str = "") -> int:
    """Mesma saida pras trilhas: status dos scanners, aceites, IA, relatorios, codigo de saida."""
    if res.rodaram:
        print(f"scanners que rodaram: {', '.join(res.rodaram)}")
    for nome, motivo in res.pulados:
        print(f"[pulado] {nome}: {motivo}")
    if res.fundidos:
        print(f"{res.fundidos} achado(s) repetido(s) entre scanners foram fundidos.")
    avisos = mod_aceitos.aplicar(res.findings)
    for a in avisos:
        print(f"[aceite] {a}")
    _narrar_com_ia(res.findings, args)
    limite = _limite(args)
    print()
    print(render(res.findings, json_tambem=getattr(args, "json", False),
                 lente=_lente(args), limite=limite))
    _salvar_ultimo(res.findings)
    meta = {"alvo": alvo, "rodaram": res.rodaram, "pulados": res.pulados,
            "fundidos": res.fundidos, "avisos": avisos}
    _exportar(res.findings, meta, args, limite)
    # codigo 1 se o deploy nao passou - serve de gate num CI/pre-commit local
    return 0 if calcular(res.findings, limite).aprovado else 1


# --------------------------------------------------------------- comandos

def cmd_demo(args) -> int:
    findings = enriquecer(_findings_demo())
    narrar(findings, None)  # demo usa so as explicacoes base
    print(render(findings, json_tambem=args.json, lente=_lente(args)))
    meta = {"alvo": "demo (dados de exemplo)", "rodaram": ["demo"], "pulados": [], "fundidos": 0}
    _exportar(findings, meta, args, Severidade.ALTO)
    return 0


def cmd_scan(args) -> int:
    return _finalizar(escanear_projeto(args.caminho), args, alvo=args.caminho)


def _opcoes_nativo(args):
    if not args.porta and not args.processo:
        return None
    return {"portas": args.porta, "processo": args.processo, "rede": args.rede}


def cmd_nativo(args) -> int:
    if args.listar:
        try:
            socks = listar_sockets()
        except ImportError:
            print("Precisa do psutil: pip install psutil")
            return 1
        print(f"{'PORTA':>6}  {'ENDERECO':<16} {'ALCANCE':<14} PROCESSO")
        for s in sorted(socks, key=lambda s: (s["porta"], s["ip"])):
            alcance = "so esta maquina" if s["ip"].startswith("127.") or s["ip"] == "::1" else "REDE"
            dono = f"{s['processo'] or '?'} (pid {s['pid']})" if s["pid"] else "? (sem permissao pra ver o dono)"
            print(f"{s['porta']:>6}  {s['ip']:<16} {alcance:<14} {dono}")
        print("\nPra avaliar o teu app: python cli.py nativo --porta <porta> [--rede]")
        return 0
    opcoes = _opcoes_nativo(args)
    if not opcoes:
        print("Diga qual e o teu app: --porta 8000 (pode repetir) e/ou --processo python")
        print("Ou veja tudo que esta escutando: python cli.py nativo --listar")
        return 2
    alvo = "portas " + ", ".join(map(str, args.porta)) if args.porta else f"processo {args.processo}"
    return _finalizar(escanear_nativo(opcoes), args, alvo=alvo)


def _portas_http(texto):
    return [int(p) for p in texto.split(",") if p.strip()]


def cmd_trafego(args) -> int:
    if args.listar_interfaces:
        if not TsharkAdapter().disponivel():
            print(TsharkAdapter().como_instalar())
            return 1
        import subprocess
        subprocess.run([tshark_binario(), "-D"])
        return 0
    try:
        portas = _portas_http(args.portas_http)
    except ValueError:
        print("--portas-http deve ser uma lista tipo 80,8080,8000")
        return 2
    opcoes = {"pcap": args.pcap, "segundos": args.segundos,
              "interface": args.interface, "portas_http": portas}
    if not args.pcap:
        print(f"Capturando HTTP sem TLS por {max(5, min(args.segundos, 300))}s. Use SO o teu app agora...")
    return _finalizar(analisar_trafego(opcoes), args, alvo=args.pcap or "captura ao vivo")


def cmd_auditar(args) -> int:
    nativo = _opcoes_nativo(args)
    trafego = None
    if args.pcap:
        trafego = {"pcap": args.pcap}
    elif args.capturar:
        trafego = {"segundos": args.capturar, "interface": args.interface,
                   "portas_http": _portas_http(args.portas_http)}
    if not (args.pasta or nativo or trafego):
        print("Diga o que auditar: uma pasta, e/ou --porta/--processo, e/ou --pcap/--capturar.")
        print("Ex.: python cli.py auditar . --porta 8000 --pcap captura.pcap --html relatorio.html")
        return 2
    trilhas = [t for t, ok in (("codigo", args.pasta), ("nativo", nativo), ("trafego", trafego)) if ok]
    print(f"Auditando: {', '.join(trilhas)}")
    if trafego and not args.pcap:
        print(f"Capturando HTTP sem TLS por {max(5, min(args.capturar, 300))}s. Use SO o teu app agora...")
    alvo = " + ".join(filter(None, [args.pasta, "portas " + ",".join(map(str, args.porta)) if args.porta else "",
                                    args.pcap or ("captura ao vivo" if trafego else "")]))
    return _finalizar(auditar(args.pasta, nativo, trafego), args, alvo=alvo)


def cmd_aceitar(args) -> int:
    fp, titulo = args.alvo, ""
    if "|" not in args.alvo:  # e um ID do ultimo relatorio
        try:
            with open(ULTIMO, encoding="utf-8") as arq:
                ultimo = json.load(arq)
        except (OSError, json.JSONDecodeError):
            print("Nao achei o ultimo relatorio. Rode um scan/auditar antes (ou passe o fingerprint).")
            return 1
        achado = next((f for f in ultimo.get("findings", []) if f["id"] == args.alvo), None)
        if not achado:
            print(f"ID {args.alvo} nao esta no ultimo relatorio ({ultimo.get('gerado_em', '?')}).")
            return 1
        fp, titulo = achado["fingerprint"], achado["titulo"]
        if achado["severidade"] == "critico":
            print("ATENCAO: voce esta aceitando um achado CRITICO. Ele vai continuar a vista no relatorio.")
    try:
        novo = mod_aceitos.aceitar(fp, args.motivo, args.dias, titulo=titulo)
    except mod_aceitos.AceiteInvalido as e:
        print(f"NAO ACEITO - {e}")
        return 1
    print(f"Aceito ate {novo['ate']}: {fp}")
    print(f"Registrado em {mod_aceitos.ARQUIVO} (commite esse arquivo pra ficar revisavel).")
    return 0


def cmd_aceitos(args) -> int:
    lista = mod_aceitos.carregar()
    if not lista:
        print("Nenhum risco aceito.")
        return 0
    hoje = dt.date.today().isoformat()
    for a in lista:
        estado = "VENCIDO" if a.get("ate", "") < hoje else f"ate {a.get('ate')}"
        print(f"[{estado}] {a.get('fingerprint')}\n          {a.get('titulo', '')} -- {a.get('motivo')}")
    return 0


def cmd_check(args) -> int:
    try:
        tipo, detalhe = autorizar_alvo(args.alvo, carregar_segredo())
    except (AlvoNaoLocal, AlvoNaoVerificado) as e:
        print(f"BLOQUEADO - {e}")
        return 1
    if tipo == "local":
        print(f"OK - alvo local. IPs: {detalhe}")
    else:
        print(f"OK - dono verificado: {detalhe} publicou o token desta semana.")
    return 0


def cmd_ia_status(args) -> int:
    ok, msg = Ollama().status()
    print(("OK - " if ok else "NAO PRONTO - ") + msg)
    return 0 if ok else 1


def cmd_segredo(args) -> int:
    s = gerar_segredo()
    print("Novo ARGOS_SECRET (guarde com cuidado, nao commite):\n")
    print(f"  ARGOS_SECRET={s}\n")
    print("1) Cole essa linha no arquivo .env da pasta do Argos.")
    print("2) Coloque o MESMO valor em Variables do teu servico no Railway.")
    print("3) Publique o endpoint de verificacao (exemplos/railway_django/argos_verify.py).")
    return 0


def cmd_token(args) -> int:
    segredo = carregar_segredo()
    if not segredo:
        print("ARGOS_SECRET nao configurado. Rode: python cli.py segredo")
        return 1
    host = args.host.split("://")[-1].split("/")[0].split(":")[0].lower()
    print(f"token desta semana p/ {host}: {token_da_semana(segredo, host)}")
    print(f"o site deve responder isso em: {url_de_verificacao(host)}")
    return 0


# --------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="argos", description="O vigia de brechas em dev/local.")
    sub = p.add_subparsers(dest="cmd", required=True)

    def comuns(sp):
        sp.add_argument("--json", action="store_true", help="inclui o JSON cru na tela")
        sp.add_argument("--lente", choices=sorted(_LENTES), help="filtra a visao do relatorio")
        sp.add_argument("--ia", action="store_true", help="explica com o Ollama local")
        sp.add_argument("--ia-max", type=int, default=10, help="max. de achados pra IA (padrao 10)")
        sp.add_argument("--html", metavar="ARQ", help="salva o relatorio HTML")
        sp.add_argument("--saida-json", metavar="ARQ", help="salva o relatorio em JSON (pra CI)")
        sp.add_argument("--falhar-em", choices=["alto", "medio", "baixo"], default="alto",
                        help="nivel que bloqueia o selo (so mais rigoroso que o padrao 'alto')")

    def nativo_opts(sp):
        sp.add_argument("--porta", type=int, action="append", default=[], help="porta do teu app (repete)")
        sp.add_argument("--processo", help="nome do processo, ex.: python, node, postgres")
        sp.add_argument("--rede", action="store_true", help="nmap tambem pelo IP da tua rede local")

    a = sub.add_parser("auditar", help="roda as trilhas pedidas e da o veredito final")
    a.add_argument("pasta", nargs="?", help="pasta do projeto (trilha de codigo)")
    nativo_opts(a)
    a.add_argument("--pcap", help="trilha de trafego a partir de uma captura")
    a.add_argument("--capturar", type=int, metavar="SEGUNDOS", help="trilha de trafego ao vivo")
    a.add_argument("--interface", help="interface pra captura ao vivo")
    a.add_argument("--portas-http", default="80,8080,8000")
    comuns(a)
    a.set_defaults(func=cmd_auditar)

    s = sub.add_parser("scan", help="trilha de codigo: escaneia um projeto local")
    s.add_argument("caminho", help="pasta do projeto a escanear")
    comuns(s)
    s.set_defaults(func=cmd_scan)

    n = sub.add_parser("nativo", help="trilha nativa: quem escuta onde (psutil + nmap)")
    nativo_opts(n)
    n.add_argument("--listar", action="store_true", help="so lista o que esta escutando (sem nota)")
    comuns(n)
    n.set_defaults(func=cmd_nativo)

    tr = sub.add_parser("trafego", help="trilha de trafego: dado sensivel em HTTP sem TLS (tshark)")
    tr.add_argument("--segundos", type=int, default=30, help="janela de captura ao vivo (5-300)")
    tr.add_argument("--interface", help="interface de captura (veja --listar-interfaces)")
    tr.add_argument("--pcap", help="analisar uma captura existente em vez de capturar")
    tr.add_argument("--portas-http", default="80,8080,8000", help="portas HTTP sem TLS a olhar")
    tr.add_argument("--listar-interfaces", action="store_true")
    comuns(tr)
    tr.set_defaults(func=cmd_trafego)

    ac = sub.add_parser("aceitar", help="aceita um risco (falso positivo) com motivo e prazo")
    ac.add_argument("alvo", help="ID do ultimo relatorio (ex.: CODE-S002) ou fingerprint")
    ac.add_argument("--motivo", required=True, help="por que isso nao e um problema (min. 10 letras)")
    ac.add_argument("--dias", type=int, default=30, help=f"validade (1 a {mod_aceitos.MAX_DIAS})")
    ac.set_defaults(func=cmd_aceitar)

    al = sub.add_parser("aceitos", help="lista os riscos aceitos e os vencimentos")
    al.set_defaults(func=cmd_aceitos)

    d = sub.add_parser("demo", help="relatorio de exemplo (sem scanner)")
    d.add_argument("--json", action="store_true", help="inclui o JSON cru")
    d.add_argument("--lente", choices=sorted(_LENTES), help="filtra a visao do relatorio")
    d.add_argument("--html", metavar="ARQ", help="salva o relatorio HTML de exemplo")
    d.add_argument("--saida-json", metavar="ARQ", help="salva o JSON de exemplo")
    d.set_defaults(func=cmd_demo)

    st = sub.add_parser("ia-status", help="confere se o Ollama local e o modelo estao prontos")
    st.set_defaults(func=cmd_ia_status)

    c = sub.add_parser("check", help="testa a trava de alvo (local ou dono verificado)")
    c.add_argument("alvo", help="ex: localhost:8000, 127.0.0.1, https://meusite.com")
    c.set_defaults(func=cmd_check)

    g = sub.add_parser("segredo", help="gera um ARGOS_SECRET novo")
    g.set_defaults(func=cmd_segredo)

    t = sub.add_parser("token", help="mostra o token da semana p/ um dominio (debug)")
    t.add_argument("host", help="ex: meusite.com")
    t.set_defaults(func=cmd_token)
    return p


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
