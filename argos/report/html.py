"""
Argos — relatório HTML (Fase 6).

Um arquivo só, que abre offline em qualquer navegador:
  - nenhum recurso externo (sem CDN, sem fonte do Google): o relatório não
    avisa ninguém que foi aberto, e uma política CSP no próprio arquivo
    bloqueia qualquer carregamento de fora;
  - TODO texto vindo de scanner/código/IA passa por html.escape — um
    relatório de segurança com XSS seria a piada perfeita.
"""
from __future__ import annotations

import datetime as dt
import html
from typing import Optional

from ..schema import Finding, Severidade, Status, FixTipo
from ..scorer import calcular, LIMITE_PADRAO
from ..lenses.lgpd_manual import CHECKLIST_LGPD, AVISO

_ROTULO = {"critico": "CRÍTICO", "alto": "ALTO", "medio": "MÉDIO", "baixo": "BAIXO", "info": "INFO"}
_ORDEM = {Severidade.CRITICO: 0, Severidade.ALTO: 1, Severidade.MEDIO: 2,
          Severidade.BAIXO: 3, Severidade.INFO: 4}


def _e(texto) -> str:
    return html.escape(str(texto or ""), quote=True)


def _cor_hp(score: int) -> str:
    return "var(--ok)" if score >= 80 else ("var(--medio)" if score >= 50 else "var(--critico)")


def _card(f: Finding) -> str:
    sev = f.severidade.value
    lentes = " ".join(l.value for l in f.lentes)
    partes = [
        f'<article class="card sev-{sev}" data-sev="{sev}" data-lentes="{_e(lentes)}">',
        '<div class="topo">',
        f'<span class="tag t-{sev}">{_ROTULO[sev]}</span>',
        f'<span class="mono">{_e(f.id)}</span>',
        f'<span class="mono cat">{_e(f.categoria)}</span>',
        "".join(f'<span class="lente">{_e(l.value)}</span>' for l in f.lentes),
        "</div>",
        f"<h3>{_e(f.titulo)}</h3>",
        '<dl>',
        f"<dt>Onde</dt><dd class=\"mono\">{_e(f.local)}</dd>",
        f"<dt>Achado por</dt><dd>{_e(f.origem)}</dd>",
    ]
    if f.evidencia:
        partes.append(f'<dt>Evidência</dt><dd class="mono">{_e(f.evidencia)}</dd>')
    partes.append("</dl>")
    if f.explicacao:
        fonte = ' <span class="fonte">IA</span>' if f.fonte_explicacao == "ia" else ""
        partes.append(f'<p class="exp"><b>Por que importa{fonte}:</b> {_e(f.explicacao)}</p>')
    if f.fix:
        tipo = "exata" if f.fix.tipo is FixTipo.DETERMINISTICO else "a revisar"
        partes.append(f'<div class="fix"><b>Correção ({tipo}):</b> {_e(f.fix.descricao)}')
        if f.fix.patch:
            partes.append(f"<pre>{_e(f.fix.patch)}</pre>")
        partes.append("</div>")
    if f.sugestao_ia:
        partes.append(f'<div class="ia"><b>Sugestão da IA — confira antes de aplicar:</b>'
                      f"<pre>{_e(f.sugestao_ia)}</pre></div>")
    if f.verificacao:
        partes.append(f'<p class="conf">✔ Confirmar: {_e(f.verificacao)}</p>')
    partes.append("</article>")
    return "".join(partes)


def render_html(findings: list[Finding], meta: Optional[dict] = None,
                limite: Severidade = LIMITE_PADRAO) -> str:
    meta = meta or {}
    placar = calcular(findings, limite)
    ativos = sorted((f for f in findings if f.status is not Status.IGNORADO),
                    key=lambda f: _ORDEM[f.severidade])
    gerado = meta.get("gerado_em") or dt.datetime.now().strftime("%d/%m/%Y %H:%M")

    def conta(pred) -> int:
        return sum(1 for f in ativos if pred(f))

    filtros = [
        ("todas", "Todas", len(ativos)),
        ("critico", "Crítico", conta(lambda f: any(l.value == "critico" for l in f.lentes))),
        ("lgpd", "LGPD", conta(lambda f: any(l.value == "lgpd" for l in f.lentes))),
        ("bot", "Bot", conta(lambda f: any(l.value == "bot" for l in f.lentes))),
        ("info", "Info / ok", conta(lambda f: f.severidade is Severidade.INFO)),
    ]
    botoes = "".join(
        f'<button data-filtro="{k}"{" class=\"ativo\"" if k == "todas" else ""}>{n} <span>{c}</span></button>'
        for k, n, c in filtros
    )
    chips = "".join(
        f'<span class="chip t-{s}">{n} {_ROTULO[s].lower()}</span>'
        for s, n in placar.por_severidade.items()
    )
    selo_cls = "selo-ok" if placar.aprovado else "selo-bloq"
    selo_txt = "OK PRA PROD" if placar.aprovado else "BLOQUEADO"
    motivo = f'<p class="motivo">{_e(placar.motivo_reprovacao)}</p>' if not placar.aprovado else ""
    if limite is not LIMITE_PADRAO:
        motivo += f'<p class="motivo">Modo rigoroso: bloqueia a partir de <b>{_e(limite.value)}</b>.</p>'

    avisos = "".join(f"<li>{_e(a)}</li>" for a in meta.get("avisos", []))
    avisos_html = f'<section class="avisos"><h2>Atenção</h2><ul>{avisos}</ul></section>' if avisos else ""

    cards = "".join(_card(f) for f in ativos) or '<p class="vazio">Nenhuma brecha encontrada pelos scanners que rodaram.</p>'

    checklist = "".join(
        f'<label><input type="checkbox"> <b>{_e(t)}</b> — {_e(x)}</label>' for t, x in CHECKLIST_LGPD
    )
    aceitos = "".join(
        f'<li><span class="tag t-{f.severidade.value}">{_ROTULO[f.severidade.value]}</span> '
        f'<b>{_e(f.titulo)}</b> <span class="mono">{_e(f.local)}</span><br><i>{_e(f.justificativa)}</i></li>'
        for f in placar.riscos_aceitos
    )
    aceitos_html = (f'<section><h2>Riscos aceitos <small>(fora do score, mas à vista)</small></h2>'
                    f'<ul class="aceitos">{aceitos}</ul></section>') if aceitos else ""

    rodaram = ", ".join(_e(r) for r in meta.get("rodaram", [])) or "nenhum"
    pulados = "".join(f"<li><b>{_e(n)}</b>: {_e(m)}</li>" for n, m in meta.get("pulados", []))
    pulados_html = f"<p>Pulados:</p><ul>{pulados}</ul>" if pulados else ""

    return _MODELO.format(
        alvo=_e(meta.get("alvo", "")),
        gerado=_e(gerado),
        score=placar.score,
        cor=_cor_hp(placar.score),
        selo_cls=selo_cls,
        selo_txt=selo_txt,
        motivo=motivo,
        chips=chips,
        avisos=avisos_html,
        botoes=botoes,
        cards=cards,
        aviso_lgpd=_e(AVISO),
        checklist=checklist,
        aceitos=aceitos_html,
        rodaram=rodaram,
        pulados=pulados_html,
        fundidos=int(meta.get("fundidos", 0)),
    )


_MODELO = """<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>Argos — relatório de brechas</title>
<style>
:root{{--bg:#0d0f14;--card:#161a22;--borda:#262b36;--txt:#e6e8ee;--sub:#9aa3b2;
--critico:#ff4d6d;--alto:#ff8c42;--medio:#ffd166;--baixo:#4cc9f0;--info:#8d99ae;--ok:#2dd4a3}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--txt);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:980px;margin:0 auto;padding:24px 18px 60px}}
header{{display:flex;align-items:center;gap:14px;margin-bottom:20px}}
header h1{{margin:0;font-size:26px;letter-spacing:.18em}}
header p{{margin:2px 0 0;color:var(--sub);font-size:13px}}
.mono{{font-family:ui-monospace,Consolas,monospace;font-size:13px}}
.placar{{background:var(--card);border:1px solid var(--borda);border-radius:14px;padding:20px;margin-bottom:18px}}
.hp{{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px}}
.hp b{{font-size:30px}}
.barra{{height:14px;background:#0a0c10;border-radius:8px;overflow:hidden;border:1px solid var(--borda)}}
.barra i{{display:block;height:100%;border-radius:8px}}
.selo{{display:inline-block;margin-top:14px;padding:6px 14px;border-radius:8px;font-weight:700;letter-spacing:.08em}}
.selo-ok{{background:rgba(45,212,163,.15);color:var(--ok);border:1px solid var(--ok)}}
.selo-bloq{{background:rgba(255,77,109,.15);color:var(--critico);border:1px solid var(--critico)}}
.motivo{{color:var(--sub);margin:8px 0 0}}
.chips{{margin-top:12px;display:flex;gap:8px;flex-wrap:wrap}}
.chip{{padding:3px 10px;border-radius:999px;font-size:13px;background:#0a0c10;border:1px solid currentColor}}
.t-critico{{color:var(--critico)}}.t-alto{{color:var(--alto)}}.t-medio{{color:var(--medio)}}.t-baixo{{color:var(--baixo)}}.t-info{{color:var(--info)}}
nav{{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0}}
nav button{{background:var(--card);color:var(--txt);border:1px solid var(--borda);border-radius:10px;padding:8px 14px;cursor:pointer;font:inherit}}
nav button span{{color:var(--sub);margin-left:4px}}
nav button.ativo{{border-color:var(--txt)}}
.card{{background:var(--card);border:1px solid var(--borda);border-left:5px solid var(--info);border-radius:12px;padding:16px 18px;margin-bottom:12px}}
.sev-critico{{border-left-color:var(--critico)}}.sev-alto{{border-left-color:var(--alto)}}
.sev-medio{{border-left-color:var(--medio)}}.sev-baixo{{border-left-color:var(--baixo)}}
.topo{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}}
.tag{{font-weight:700;font-size:12px;letter-spacing:.06em}}
.cat{{color:var(--sub)}}
.lente{{font-size:11px;padding:1px 8px;border-radius:999px;background:#0a0c10;color:var(--sub);border:1px solid var(--borda)}}
.card h3{{margin:8px 0 10px;font-size:16px}}
dl{{display:grid;grid-template-columns:110px 1fr;gap:4px 12px;margin:0 0 10px}}
dt{{color:var(--sub)}} dd{{margin:0;word-break:break-word}}
.exp,.conf{{margin:8px 0}} .conf{{color:var(--sub);font-size:14px}}
.fonte{{font-size:11px;padding:0 6px;border-radius:6px;background:#2b2140;color:#c4a7ff}}
.fix,.ia{{background:#0f1218;border:1px solid var(--borda);border-radius:8px;padding:10px 12px;margin:8px 0}}
.ia{{border-color:#3b2f57}}
pre{{white-space:pre-wrap;word-break:break-word;margin:8px 0 0;font:13px/1.45 ui-monospace,Consolas,monospace;color:#cfd6e4}}
section{{background:var(--card);border:1px solid var(--borda);border-radius:14px;padding:18px;margin-top:18px}}
section h2{{margin:0 0 10px;font-size:17px}} section h2 small{{color:var(--sub);font-weight:400}}
.avisos{{border-color:var(--medio)}}
.lgpd label{{display:block;padding:6px 0;border-bottom:1px solid var(--borda)}}
.lgpd p{{color:var(--sub);margin:0 0 8px}}
.aceitos li{{margin-bottom:10px}}
.vazio{{color:var(--sub)}}
footer{{color:var(--sub);font-size:12px;margin-top:28px;text-align:center}}
.oculto{{display:none}}
</style></head>
<body><div class="wrap">
<header>
<svg width="52" height="32" viewBox="0 0 52 32" aria-hidden="true"><path d="M2 16C10 4 42 4 50 16C42 28 10 28 2 16Z" fill="none" stroke="#e6e8ee" stroke-width="2.5"/><circle cx="26" cy="16" r="8" fill="#2dd4a3"/><circle cx="26" cy="16" r="3.5" fill="#0d0f14"/></svg>
<div><h1>ARGOS</h1><p>Relatório de brechas · {alvo} · {gerado}</p></div>
</header>
<div class="placar">
<div class="hp"><span>HP do deploy</span><b>{score}/100</b></div>
<div class="barra"><i style="width:{score}%;background:{cor}"></i></div>
<div class="selo {selo_cls}">{selo_txt}</div>{motivo}
<div class="chips">{chips}</div>
</div>
{avisos}
<nav>{botoes}</nav>
<main id="lista">{cards}</main>
<section class="lgpd"><h2>Checklist manual LGPD <small>(fora do score · as marcações não são salvas)</small></h2>
<p>{aviso_lgpd}</p>{checklist}</section>
{aceitos}
<section><h2>Scanners</h2><p>Rodaram: {rodaram}</p>{pulados}<p>Achados repetidos fundidos: {fundidos}</p></section>
<footer>Gerado pelo Argos — só dev/local. Explicações marcadas como IA são sugestões: confira antes de aplicar.</footer>
</div>
<script>
(function(){{
  var bts=document.querySelectorAll('nav button'),cards=document.querySelectorAll('.card');
  bts.forEach(function(b){{b.addEventListener('click',function(){{
    bts.forEach(function(x){{x.classList.remove('ativo')}});b.classList.add('ativo');
    var f=b.getAttribute('data-filtro');
    cards.forEach(function(c){{
      var lentes=(c.getAttribute('data-lentes')||'').split(' '),sev=c.getAttribute('data-sev');
      var ver=f==='todas'||(f==='info'?sev==='info':lentes.indexOf(f)>=0);
      c.classList.toggle('oculto',!ver);
    }});
  }})}});
}})();
</script>
</body></html>
"""
