/* Argos — a tela. Fala com o Python pela ponte do pywebview (window.pywebview.api).
 * Aberto direto num navegador, usa dados de demonstração (modo prévia).
 *
 * Regra de segurança: todo texto vindo de scanner, código ou IA entra na tela
 * por textContent — nunca por innerHTML. Os únicos innerHTML são ícones fixos.
 */
(function () {
  "use strict";

  const $ = s => document.querySelector(s);
  const $$ = s => Array.from(document.querySelectorAll(s));
  const SEV_ROTULO = { critico: "CRÍTICO", alto: "ALTO", medio: "MÉDIO", baixo: "BAIXO", info: "INFO" };
  const SEV_NOME = { critico: "crítico", alto: "alto", medio: "médio", baixo: "baixo" };
  const ICONES = {
    critico: '<svg class="ico-sev" viewBox="0 0 16 16"><path d="M8 1.5 15 14H1z"/></svg>',
    alto: '<svg class="ico-sev" viewBox="0 0 16 16"><path d="M8 1 15 8 8 15 1 8z"/></svg>',
    medio: '<svg class="ico-sev" viewBox="0 0 16 16"><rect x="2" y="2" width="12" height="12" rx="3"/></svg>',
    baixo: '<svg class="ico-sev" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6.5"/></svg>',
    info: '<svg class="ico-sev" viewBox="0 0 16 16"><circle cx="8" cy="8" r="5.5" fill="none" stroke="var(--sev)" stroke-width="2"/></svg>',
    check: '<svg viewBox="0 0 16 16"><path d="M3 8.5 6.5 12 13 4.5"/></svg>',
    ok: '<svg viewBox="0 0 24 24"><path d="M5 12.5 10 17 19 7"/></svg>',
    x: '<svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></svg>',
    traco: '<svg viewBox="0 0 24 24"><path d="M6 12h12"/></svg>',
    resolvido: '<svg class="ico-ok" viewBox="0 0 24 24"><path d="M5 12.5 10 17 19 7"/></svg>',
    aviso: '<svg class="ico-av" viewBox="0 0 24 24"><path d="M12 4 21 20H3z"/><path d="M12 10v4M12 17h.01"/></svg>',
    scan: '<svg class="ico-sc" viewBox="0 0 24 24"><circle cx="11" cy="11" r="6"/><path d="m20 20-4-4"/></svg>',
  };

  const app = {
    conj: { auditoria: null, ia: null },
    sel: { auditoria: null, ia: null },
    filtro: "todas",
    ocupado: null,
    modoIA: "ollama",
    vigia: null,
    aceitarAlvo: null,
    log: { pos: 0, t0: 0, ultimaEm: 0, ultima: "", aberto: false, recolhido: false },
  };

  // ------------------------------------------------------------ ponte

  async function api(metodo, ...args) {
    const p = window.pywebview && window.pywebview.api;
    if (p && p[metodo]) return await p[metodo](...args);
    return Previa[metodo] ? Previa[metodo](...args) : null;
  }

  function el(tag, cls, texto) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (texto !== undefined && texto !== null) e.textContent = texto;
    return e;
  }

  function toast(msg, erro) {
    const t = el("div", "toast" + (erro ? " erro-t" : ""), msg);
    $("#toasts").appendChild(t);
    setTimeout(() => t.remove(), 4800);
  }

  // ------------------------------------------------------------ humor (olho + cor)

  const FRASES = {
    repouso: ["Em repouso", "Escolha o que vigiar e clique em Auditar."],
    vigiando: ["Vigiando…", "Os cem olhos estão olhando. Isso pode levar alguns minutos."],
    alerta: ["Brechas que bloqueiam o deploy", ""],
    ressalva: ["Passou, com ressalvas", ""],
    ok: ["Tudo limpo", "Nenhuma brecha aberta nos scanners que rodaram."],
  };
  const PILULA = { repouso: "Em repouso", vigiando: "Vigiando", alerta: "Achou brechas", ressalva: "Com ressalvas", ok: "Tudo limpo" };

  function humor(h, pacote) {
    document.body.dataset.humor = h;
    app.vigia.definir(h);
    $("#estado-txt").textContent = PILULA[h];
    const [frase, sub] = FRASES[h];
    $("#frase").textContent = frase;
    let s = sub;
    if (pacote && h === "alerta") s = `${pacote.placar.bloqueantes} brecha(s) crítica(s) ou alta(s) aberta(s). Veja o checklist.`;
    if (pacote && h === "ressalva") s = `Nada bloqueia, mas há ${pacote.placar.total} ponto(s) pra melhorar.`;
    $("#subfrase").textContent = s;
  }

  // ------------------------------------------------------------ auditoria

  function corScore(score) {
    return score >= 80 ? "#2dd4a3" : score >= 50 ? "#ffd166" : "#ff4d6d";
  }

  function renderPlacar() {
    const p = app.conj.auditoria;
    const raiz = $(".placar");
    const hp = $("#hp");
    if (!hp.children.length) for (let i = 0; i < 20; i++) hp.appendChild(el("i"));
    const chips = $("#sev-chips");
    chips.textContent = "";
    if (!p) {
      raiz.style.removeProperty("--cor-score");
      $("#score").textContent = "—";
      $("#anel-valor").style.strokeDashoffset = 314.16;
      Array.from(hp.children).forEach(i => i.classList.remove("on"));
      const selo = $("#selo");
      selo.className = "selo";
      selo.textContent = "SEM AUDITORIA";
      $("#placar-motivo").textContent = "O veredito aparece aqui.";
      ["critico", "alto", "medio", "baixo"].forEach(s => chips.appendChild(chip(s, 0)));
      progresso(0, 0);
      return;
    }
    const pl = p.placar;
    raiz.style.setProperty("--cor-score", corScore(pl.score));
    animarNumero($("#score"), pl.score);
    $("#anel-valor").style.strokeDashoffset = (314.16 * (1 - pl.score / 100)).toFixed(1);
    const cheios = Math.round(pl.score / 5);
    Array.from(hp.children).forEach((i, n) => i.classList.toggle("on", n < cheios));
    const selo = $("#selo");
    selo.className = "selo " + (pl.aprovado ? "ok" : "bloq");
    selo.textContent = pl.aprovado ? "OK PRA PROD" : "BLOQUEADO";
    $("#placar-motivo").textContent = pl.aprovado
      ? "Nenhuma brecha crítica ou alta aberta."
      : `${pl.bloqueantes} crítica(s)/alta(s) barram o deploy.`;
    ["critico", "alto", "medio", "baixo"].forEach(s => chips.appendChild(chip(s, pl.por_severidade[s] || 0)));
    progresso(pl.feitos, pl.total);
  }

  function chip(sev, n) {
    const c = el("div", "sev-chip s-" + sev + (n ? "" : " zero"));
    const ic = el("span");
    ic.innerHTML = ICONES[sev];
    c.appendChild(ic);
    const t = el("div");
    t.appendChild(el("b", null, String(n)));
    t.appendChild(el("small", null, SEV_NOME[sev]));
    c.appendChild(t);
    return c;
  }

  function progresso(feitos, total) {
    $("#prog-txt").textContent = `Checklist: ${feitos} de ${total} marcadas`;
    $("#prog-barra").style.width = total ? (100 * feitos / total) + "%" : "0";
  }

  function animarNumero(alvo, valor) {
    const ini = parseInt(alvo.textContent, 10);
    const de = isNaN(ini) ? 0 : ini;
    const t0 = performance.now();
    const passo = t => {
      const k = Math.min(1, (t - t0) / 700);
      const e = 1 - Math.pow(1 - k, 3);
      alvo.textContent = String(Math.round(de + (valor - de) * e));
      if (k < 1) requestAnimationFrame(passo);
    };
    requestAnimationFrame(passo);
  }

  function renderResumo() {
    const caixa = $("#resumo");
    caixa.textContent = "";
    const p = app.conj.auditoria;
    if (!p) { caixa.appendChild(el("p", "vazio", "Rode uma auditoria pra ver o que mudou.")); return; }
    const linha = (ico, titulo, sub) => {
      const l = el("div", "linha-resumo");
      const i = el("span"); i.innerHTML = ICONES[ico]; l.appendChild(i);
      const t = el("div"); t.appendChild(el("p", null, titulo)); if (sub) t.appendChild(el("small", null, sub));
      l.appendChild(t);
      caixa.appendChild(l);
    };
    if (p.resolvidos.length) linha("resolvido", `${p.resolvidos.length} brecha(s) resolvida(s)`, p.resolvidos.slice(0, 3).join(" · "));
    linha("scan", `${p.meta.rodaram.length} scanner(s) rodaram`, p.meta.alvo || "");
    if (p.meta.pulados.length) linha("aviso", `${p.meta.pulados.length} pulado(s)`, p.meta.pulados.map(x => x[0]).join(", ") + " — veja a aba Scanners");
    (p.meta.avisos || []).forEach(a => linha("aviso", "Aviso", a));
    if (p.meta.fundidos) linha("scan", `${p.meta.fundidos} achado(s) repetido(s) fundidos`, "a mesma brecha achada por scanners diferentes conta uma vez");
  }

  // ------------------------------------------------------------ listas

  function filtrar(itens) {
    const f = app.filtro;
    if (f === "todas") return itens;
    if (f === "info") return itens.filter(x => x.sev === "info");
    return itens.filter(x => x.lentes.indexOf(f) >= 0);
  }

  function item(f, conj, aoSelecionar) {
    const d = el("div", "item s-" + f.sev + (f.feito ? " feito" : ""));
    if (app.sel[conj] === f.fp) d.classList.add("sel");
    if (f.conta) {
      const b = el("button", "chk");
      b.title = "Marcar como corrigida";
      b.innerHTML = ICONES.check;
      b.addEventListener("click", async ev => {
        ev.stopPropagation();
        const r = await api("alternar", conj, f.fp);
        if (!r) return;
        f.feito = r.feito;
        d.classList.toggle("feito", r.feito);
        app.conj[conj].placar.feitos = r.feitos;
        if (conj === "auditoria") progresso(r.feitos, r.total);
        if (app.sel[conj] === f.fp) aoSelecionar(f);
      });
      d.appendChild(b);
    } else {
      d.appendChild(el("span", "chk-vazio"));
    }
    const ic = el("span"); ic.innerHTML = ICONES[f.sev]; d.appendChild(ic);
    const txt = el("div");
    txt.appendChild(el("div", "item-tit", f.titulo));
    txt.appendChild(el("div", "item-sub", `${f.local}  ·  ${f.origem}`));
    d.appendChild(txt);
    d.appendChild(el("span", "tag", SEV_ROTULO[f.sev]));
    d.addEventListener("click", () => {
      app.sel[conj] = f.fp;
      d.parentNode.querySelectorAll(".item").forEach(x => x.classList.remove("sel"));
      d.classList.add("sel");
      aoSelecionar(f);
    });
    return d;
  }

  function vazioLista(caixa, titulo, sub) {
    const v = el("div", "lista-vazia");
    v.appendChild(el("b", null, titulo));
    v.appendChild(el("span", null, sub));
    caixa.appendChild(v);
  }

  function detalhe(caixa, f, conj) {
    caixa.textContent = "";
    if (!f) {
      const v = el("div", "detalhe-vazio");
      const o = el("div", "olho"); v.appendChild(o);
      new ArgosOlho.Olho(o).olhar(-0.35, 0.2);
      v.appendChild(el("p", null, "Clique numa brecha pra ver o porquê, a correção e como confirmar."));
      caixa.appendChild(v);
      return;
    }
    caixa.appendChild(el("h4", null, f.titulo));
    const meta = el("div", "meta s-" + f.sev);
    meta.appendChild(el("span", "tag", SEV_ROTULO[f.sev]));
    meta.appendChild(el("span", null, f.categoria));
    meta.appendChild(el("span", null, f.local));
    meta.appendChild(el("span", null, "achado por " + f.origem));
    caixa.appendChild(meta);
    const sec = (rot, texto, codigo, selo) => {
      if (!texto) return;
      const s = el("div", "sec");
      const r = el("small", null, rot);
      if (selo) r.appendChild(el("em", null, selo));
      s.appendChild(r);
      s.appendChild(el(codigo ? "pre" : "p", null, texto));
      caixa.appendChild(s);
    };
    sec("EVIDÊNCIA", f.evidencia, true);
    sec("POR QUE IMPORTA", f.explicacao, false, f.fonte === "ia" ? "IA" : "");
    if (f.fix) {
      sec(f.fix.tipo === "deterministico" ? "CORREÇÃO EXATA" : "CORREÇÃO A REVISAR", f.fix.descricao);
      if (f.fix.patch) caixa.lastChild.appendChild(el("pre", null, f.fix.patch));
    }
    sec("SUGESTÃO DA IA — CONFIRA ANTES DE APLICAR", f.sugestao, true);
    sec("COMO CONFIRMAR", f.verificacao);
    if (f.conta) {
      const acoes = el("div", "acoes");
      const marcar = el("button", "btn", f.feito ? "Desmarcar" : "Marcar como corrigida");
      marcar.addEventListener("click", () => {
        const alvo = $(`#${conj === "ia" ? "lista-ia" : "lista-brechas"} .item.sel .chk`);
        if (alvo) alvo.click();
      });
      const aceitar = el("button", "btn", "Aceitar como falso positivo…");
      aceitar.addEventListener("click", () => abrirAceitar(f, conj));
      acoes.appendChild(marcar);
      acoes.appendChild(aceitar);
      caixa.appendChild(acoes);
    }
  }

  function renderBrechas() {
    const p = app.conj.auditoria;
    const caixa = $("#lista-brechas");
    caixa.textContent = "";
    const det = $("#detalhe-brechas");
    if (!p) {
      vazioLista(caixa, "Nenhuma auditoria ainda", "Rode uma auditoria na aba Auditoria.");
      detalhe(det, null);
      return;
    }
    const itens = filtrar(p.findings);
    if (!itens.length) vazioLista(caixa, p.findings.length ? "Nada nesta lente" : "Nenhuma brecha encontrada",
      "Os scanners que rodaram não acharam nada aqui.");
    const mostrar = f => detalhe(det, f, "auditoria");
    itens.forEach(f => caixa.appendChild(item(f, "auditoria", mostrar)));
    const sel = p.findings.find(f => f.fp === app.sel.auditoria);
    detalhe(det, sel || null, "auditoria");
    const abertas = p.findings.filter(f => f.conta && !f.feito).length;
    const badge = $("#badge-brechas");
    badge.textContent = abertas ? String(abertas) : "";
    badge.classList.toggle("quente", p.placar.bloqueantes > 0);
  }

  function renderLgpd() {
    const p = app.conj.auditoria;
    const caixa = $("#lista-lgpd");
    caixa.textContent = "";
    const itens = (p && p.lgpd) || app.lgpdBase || [];
    const feitos = itens.filter(x => x.feito).length;
    const cont = $("#lgpd-cont");
    cont.textContent = "";
    cont.appendChild(el("span", null, `${feitos} de ${itens.length}`));
    const b = el("div", "barra"); const i = el("i"); i.style.width = itens.length ? (100 * feitos / itens.length) + "%" : "0";
    b.appendChild(i); cont.appendChild(b);
    itens.forEach((x, n) => {
      const d = el("div", "item item-lgpd" + (x.feito ? " feito" : ""));
      const c = el("button", "chk"); c.innerHTML = ICONES.check;
      d.appendChild(c);
      const t = el("div");
      t.appendChild(el("div", "item-tit", x.titulo));
      t.appendChild(el("div", "item-sub", x.texto));
      d.appendChild(t);
      d.addEventListener("click", async () => {
        const r = await api("alternar_lgpd", n);
        if (!r) return;
        x.feito = r.feito;
        renderLgpd();
      });
      caixa.appendChild(d);
    });
  }

  function renderScanners() {
    const caixa = $("#scanners");
    caixa.textContent = "";
    const blocos = ["auditoria", "ia"].map(c => app.conj[c]).filter(Boolean);
    if (!blocos.length) { caixa.appendChild(el("p", "vazio", "Rode uma auditoria pra ver quais scanners participaram.")); return; }
    blocos.forEach(p => {
      caixa.appendChild(el("h3", null, p.meta.alvo || "Última execução"));
      p.meta.rodaram.forEach(r => {
        const l = el("div", "scan-linha rodou"); l.appendChild(el("i"));
        const t = el("div"); t.appendChild(el("b", null, r)); t.appendChild(el("small", null, "rodou")); l.appendChild(t);
        caixa.appendChild(l);
      });
      p.meta.pulados.forEach(([n, m]) => {
        const l = el("div", "scan-linha pulou"); l.appendChild(el("i"));
        const t = el("div"); t.appendChild(el("b", null, n)); t.appendChild(el("small", null, m)); l.appendChild(t);
        caixa.appendChild(l);
      });
      if (p.meta.nota_ia) caixa.appendChild(el("p", "vazio", "IA: " + p.meta.nota_ia));
    });
  }

  // ------------------------------------------------------------ IA

  const CATS = [
    { id: "vazamento", nome: "Vazamento do prompt", owasp: "LLM07" },
    { id: "sobrescrita", nome: "Sobrescrita de regras", owasp: "LLM01" },
    { id: "indireta", nome: "Injeção indireta", owasp: "LLM01" },
  ];

  function renderIA() {
    const tiles = $("#tiles-ia");
    tiles.textContent = "";
    const p = app.conj.ia;
    CATS.forEach(c => {
      const f = p && p.findings.find(x => x.local.endsWith("· " + c.id));
      let cls = "nada", txt = "Não testado", ico = "traco";
      if (f && f.sev === "info" && f.categoria === "IA-OK") { cls = "ok"; txt = "Resistiu"; ico = "ok"; }
      else if (f && f.sev !== "info") { cls = f.sev === "medio" ? "medio" : "ruim"; txt = "Vulnerável"; ico = "x"; }
      const t = el("div", "tile " + cls);
      t.appendChild(el("small", null, c.owasp));
      t.appendChild(el("b", null, c.nome));
      const st = el("span", "st"); st.innerHTML = ICONES[ico]; st.appendChild(el("span", null, txt));
      t.appendChild(st);
      tiles.appendChild(t);
    });
    const caixa = $("#lista-ia");
    caixa.textContent = "";
    const det = $("#detalhe-ia");
    if (!p) {
      vazioLista(caixa, "A tua IA ainda não foi testada", "Cole o prompt de sistema e clique em Testar minha IA.");
      detalhe(det, null);
      $("#badge-ia").textContent = "";
      return;
    }
    const mostrar = f => detalhe(det, f, "ia");
    p.findings.forEach(f => caixa.appendChild(item(f, "ia", mostrar)));
    detalhe(det, p.findings.find(f => f.fp === app.sel.ia) || null, "ia");
    const ruins = p.findings.filter(f => f.conta).length;
    const badge = $("#badge-ia");
    badge.textContent = ruins ? String(ruins) : "";
    badge.classList.toggle("quente", ruins > 0);
  }

  // ------------------------------------------------------------ ações

  // ------------------------------------------------------------ console (log ao vivo + cancelar)

  const ROTULO_FIM = { ok: "Concluído", cancelado: "Cancelado", erro: "Parou com erro" };

  function consoleAbrir(nome) {
    const c = $("#console");
    app.log = { pos: 0, t0: Date.now(), ultimaEm: Date.now(), ultima: "começando…", aberto: true,
                recolhido: app.log.recolhido };
    $("#console-linhas").textContent = "";
    $("#console-tit").textContent = nome === "ia" ? "Testando a IA" : "Vigiando";
    $("#console-agora").textContent = "começando…";
    $("#console-agora").classList.remove("devagar");
    $("#console-tempo").textContent = "0 s";
    const b = $("#btn-cancelar");
    b.disabled = false; b.textContent = "Cancelar"; b.classList.remove("oculto");
    $("#console-fechar").classList.add("oculto");
    c.classList.remove("oculto", "parado");
    delete c.dataset.fim;
    c.classList.toggle("recolhido", app.log.recolhido);
    $("#console-recolher").textContent = app.log.recolhido ? "Ver log" : "Esconder log";
    document.body.classList.add("com-console");
    document.body.classList.toggle("console-baixo", app.log.recolhido);
  }

  function consoleLinhas(linhas) {
    if (!linhas || !linhas.length) return;
    const ol = $("#console-linhas");
    const noFim = ol.scrollHeight - ol.scrollTop - ol.clientHeight < 30;
    linhas.forEach(l => {
      const li = el("li");
      li.appendChild(el("time", null, l.t.toFixed(1) + " s"));
      li.appendChild(el("span", "t-" + (l.tipo || "info"), l.msg));
      ol.appendChild(li);
    });
    while (ol.children.length > 400) ol.removeChild(ol.firstChild);
    if (noFim) ol.scrollTop = ol.scrollHeight;
    const ultima = linhas[linhas.length - 1];
    app.log.ultima = ultima.msg;
    app.log.ultimaEm = Date.now();
  }

  function consoleTique(cancelando) {
    if (!app.log.aberto || $("#console").classList.contains("parado")) return;
    const seg = Math.floor((Date.now() - app.log.t0) / 1000);
    $("#console-tempo").textContent = seg < 60 ? `${seg} s` : `${Math.floor(seg / 60)} min ${seg % 60} s`;
    const quieto = Math.floor((Date.now() - app.log.ultimaEm) / 1000);
    const agora = $("#console-agora");
    // sem linha nova faz tempo: deixa claro que ainda está trabalhando nessa etapa
    agora.textContent = quieto >= 6 ? `${app.log.ultima} · ainda trabalhando nisso (${quieto} s)` : app.log.ultima;
    agora.classList.toggle("devagar", quieto >= 20);
    if (cancelando) {
      const b = $("#btn-cancelar");
      b.disabled = true; b.textContent = "Cancelando…";
      $("#console-tit").textContent = "Cancelando";
    }
  }

  function consoleFim(tipo) {
    const c = $("#console");
    c.classList.add("parado");
    c.dataset.fim = tipo;
    $("#console-tit").textContent = ROTULO_FIM[tipo];
    $("#console-agora").classList.remove("devagar");
    $("#console-agora").textContent = app.log.ultima;
    $("#btn-cancelar").classList.add("oculto");
    $("#console-fechar").classList.remove("oculto");
  }

  function consoleFechar() {
    app.log.aberto = false;
    $("#console").classList.add("oculto");
    document.body.classList.remove("com-console", "console-baixo");
  }

  function consoleRecolher() {
    app.log.recolhido = !app.log.recolhido;
    $("#console").classList.toggle("recolhido", app.log.recolhido);
    document.body.classList.toggle("console-baixo", app.log.recolhido);
    $("#console-recolher").textContent = app.log.recolhido ? "Ver log" : "Esconder log";
    if (!app.log.recolhido) { const ol = $("#console-linhas"); ol.scrollTop = ol.scrollHeight; }
  }

  async function cancelar() {
    const b = $("#btn-cancelar");
    b.disabled = true; b.textContent = "Cancelando…";
    const r = await api("cancelar");
    if (r && r.erro) { toast(r.erro, true); b.disabled = false; b.textContent = "Cancelar"; }
  }

  // ------------------------------------------------------------ relatório pra IA

  async function copiarTexto(texto) {
    try {
      if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(texto); return true; }
    } catch (e) { /* cai no plano B */ }
    const area = el("textarea");
    area.value = texto;
    area.setAttribute("readonly", "");
    area.style.position = "fixed"; area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    area.remove();
    return ok;
  }

  async function copiarPraIA() {
    const r = await api("texto_ia", "auditoria");
    if (!r || r.erro) { toast(r ? r.erro : "Não consegui montar o relatório.", true); return; }
    if (await copiarTexto(r.texto)) {
      toast("Copiado! Cole no Claude e peça: \"corrija essas brechas\".");
    } else {
      toast("Não deu pra copiar aqui; vou salvar num arquivo .md.");
      const s = await api("exportar_ia", "auditoria");
      if (s && s.ok) toast("Relatório pra IA salvo: " + s.ok);
    }
  }

  function ocupar(nome) {
    if (nome && app.ocupado !== nome) consoleAbrir(nome);
    app.ocupado = nome;
    const botoes = { auditoria: $("#btn-auditar"), ia: $("#btn-ia") };
    Object.entries(botoes).forEach(([k, b]) => {
      b.disabled = !!nome;
      b.textContent = "";
      if (nome === k) { b.appendChild(el("i", "gira")); b.appendChild(el("span", null, k === "ia" ? "Testando a IA…" : "Vigiando…")); }
      else b.appendChild(el("span", null, k === "ia" ? "Testar minha IA" : "Auditar"));
    });
    if (nome) humor("vigiando");
  }

  async function auditar() {
    const params = {
      pasta: $("#in-pasta").value.trim(), portas: $("#in-portas").value.trim(),
      pcap: $("#in-pcap").value.trim(), urls: $("#in-urls").value.trim(), rede: $("#in-rede").checked, ia: $("#in-ia").checked,
    };
    const r = await api("auditar", params);
    if (!r || r.erro) { toast(r ? r.erro : "Não consegui iniciar.", true); return; }
    ocupar("auditoria");
  }

  async function testarIA() {
    const params = app.modoIA === "http"
      ? { modo: "http", url: $("#ia-url").value.trim(), campo_entrada: $("#ia-entrada").value.trim(),
          campo_saida: $("#ia-saida").value.trim(), canario: $("#ia-canario").value.trim() }
      : { modo: "ollama", modelo: $("#ia-modelo").value.trim(), sistema: $("#ia-sistema").value };
    const r = await api("testar_ia", params);
    if (!r || r.erro) { toast(r ? r.erro : "Não consegui iniciar.", true); return; }
    ocupar("ia");
  }

  let sondando = false;
  async function sondar() {
    if (!app.ocupado || sondando) return;
    sondando = true;
    let s;
    try { s = await api("status", app.log.pos); } finally { sondando = false; }
    if (!s) return;
    if (typeof s.pos === "number") {
      consoleLinhas(s.log);
      app.log.pos = s.pos;
    }
    consoleTique(s.cancelando);
    if (s.ocupado) return;
    const nome = app.ocupado;
    ocupar(null);
    const anterior = app.conj[s.conj || nome];
    if (s.cancelado) {
      consoleFim("cancelado");
      toast("Vigia cancelada. Os resultados anteriores continuam na tela.");
      humor(anterior ? anterior.humor : "repouso", anterior);
      return;
    }
    if (s.erro) {
      consoleFim("erro");
      toast("Erro: " + s.erro, true);
      humor("repouso");
      return;
    }
    consoleFim("ok");
    app.conj[s.conj] = s.dados;
    app.sel[s.conj] = null;
    humor(s.dados.humor, s.dados);
    renderTudo();
    if (nome === "auditoria") toast(`Auditoria concluída: ${s.dados.findings.length} achado(s).`);
    else toast("Teste de IA concluído.");
  }

  function renderTudo() {
    renderPlacar();
    renderResumo();
    renderBrechas();
    renderLgpd();
    renderIA();
    renderScanners();
  }

  function abrirAceitar(f, conj) {
    app.aceitarAlvo = { f, conj };
    $("#modal-tit").textContent = f.titulo;
    $("#modal-motivo").value = "";
    $("#modal-dias").value = "30";
    $("#modal-erro").textContent = "";
    $("#modal").classList.remove("oculto");
    $("#modal-motivo").focus();
  }

  async function confirmarAceite() {
    const { f, conj } = app.aceitarAlvo;
    const r = await api("aceitar", f.fp, f.titulo, $("#modal-motivo").value, $("#modal-dias").value);
    if (!r || r.erro) { $("#modal-erro").textContent = r ? r.erro : "Erro ao aceitar."; return; }
    $("#modal").classList.add("oculto");
    toast(`Risco aceito até ${r.ate}. Vale a partir do próximo scan.`);
    void conj;
  }

  function trocarView(v) {
    $$(".nav").forEach(b => b.classList.toggle("ativo", b.dataset.view === v));
    $$(".view").forEach(s => s.classList.toggle("ativa", s.id === "view-" + v));
  }

  function ligar() {
    $$(".nav").forEach(b => b.addEventListener("click", () => trocarView(b.dataset.view)));
    $$("#filtros .chip").forEach(b => b.addEventListener("click", () => {
      app.filtro = b.dataset.filtro;
      $$("#filtros .chip").forEach(x => x.classList.toggle("ativo", x === b));
      renderBrechas();
    }));
    $("#btn-auditar").addEventListener("click", auditar);
    $("#btn-cancelar").addEventListener("click", cancelar);
    $("#console-recolher").addEventListener("click", consoleRecolher);
    $("#console-fechar").addEventListener("click", consoleFechar);
    $("#btn-ia").addEventListener("click", testarIA);
    $("#btn-copiar-ia").addEventListener("click", copiarPraIA);
    $("#btn-salvar-ia").addEventListener("click", async () => {
      const r = await api("exportar_ia", "auditoria");
      if (r && r.erro) toast(r.erro, true); else if (r && r.ok) toast("Relatório pra IA salvo: " + r.ok);
    });
    $("#btn-exportar").addEventListener("click", async () => {
      const r = await api("exportar_html", "auditoria");
      if (r && r.erro) toast(r.erro, true); else if (r && r.ok) toast("Relatório salvo: " + r.ok);
    });
    $$("[data-escolher]").forEach(b => b.addEventListener("click", async () => {
      const tipo = b.dataset.escolher;
      const c = await api("escolher", tipo);
      if (c) $(tipo === "pasta" ? "#in-pasta" : "#in-pcap").value = c;
    }));
    $$("#seg-ia button").forEach(b => b.addEventListener("click", () => {
      app.modoIA = b.dataset.modo;
      $$("#seg-ia button").forEach(x => x.classList.toggle("ativo", x === b));
      $("#modo-ollama").classList.toggle("oculto", app.modoIA !== "ollama");
      $("#modo-http").classList.toggle("oculto", app.modoIA !== "http");
    }));
    $("#ia-arquivo").addEventListener("click", async () => {
      const r = await api("abrir_texto");
      if (r && r.erro) toast(r.erro, true); else if (r && r.texto !== undefined) $("#ia-sistema").value = r.texto;
    });
    $$("[data-exemplo]").forEach(b => b.addEventListener("click", async () => {
      $("#ia-sistema").value = (await api("exemplo_prompt", b.dataset.exemplo)) || "";
    }));
    $("#ia-gerar").addEventListener("click", async () => {
      const c = await api("gerar_canario");
      $("#ia-canario").value = c;
      toast("Plante esse canário no prompt de sistema do teu app antes de testar.");
    });
    $("#modal-cancelar").addEventListener("click", () => $("#modal").classList.add("oculto"));
    $("#modal-ok").addEventListener("click", confirmarAceite);
    document.addEventListener("keydown", e => { if (e.key === "Escape") $("#modal").classList.add("oculto"); });
  }

  async function iniciar() {
    app.vigia = new ArgosOlho.Vigia($("#palco"), { enxame: 16 });
    const logo = new ArgosOlho.Olho($("#olho-logo"));
    app.vigia.acompanhar(logo);
    ligar();
    const ini = await api("inicio");
    $("#versao-num").textContent = "v" + ini.versao;
    $("#ia-modelo").value = ini.modelo || "";
    $("#lgpd-aviso").textContent = ini.aviso_lgpd;
    app.lgpdBase = ini.lgpd;
    app.conj.auditoria = ini.auditoria;
    app.conj.ia = ini.ia;
    renderTudo();
    humor(ini.auditoria ? ini.auditoria.humor : "repouso", ini.auditoria);
    if (ini.ocupado) ocupar(ini.ocupado);
    setInterval(sondar, 400);
  }

  // ------------------------------------------------------------ prévia no navegador (sem Python)

  const Previa = (function () {
    const lg = [
      ["Base legal", "Cada dado pessoal coletado tem base legal definida (ex.: consentimento) — art. 7º."],
      ["Minimização", "Só coleta o necessário pra finalidade (princípio da necessidade) — art. 6º, III."],
      ["Direitos do titular", "Existe canal pro titular pedir acesso, correção e eliminação dos dados — art. 18."],
    ].map(([titulo, texto]) => ({ titulo, texto, feito: false }));
    const f = (fp, sev, titulo, local, origem, cat, lentes, extra) => Object.assign({
      fp, id: fp, sev, titulo, local, origem, categoria: cat, lentes, conta: sev !== "info", feito: false,
      evidencia: "", explicacao: "", fonte: "template", sugestao: "", verificacao: "", fix: null,
    }, extra || {});
    const demo = () => ({
      humor: "alerta",
      placar: { score: 30, aprovado: false, bloqueantes: 2, por_severidade: { critico: 1, alto: 1, medio: 1 }, feitos: 0, total: 3 },
      findings: [
        f("a", "critico", "Chave de API escrita direto no código", "config/settings.py:42", "gitleaks", "CWE-798", ["critico", "lgpd"],
          { evidencia: "API_KEY = 'sk-l***e1'", explicacao: "Credencial escrita no código vai junto pro git e pra toda cópia do projeto.",
            fix: { tipo: "ia", descricao: "Mover pra variável de ambiente (.env).", patch: "API_KEY = os.getenv('API_KEY')" },
            verificacao: "re-rodar gitleaks → 0 ocorrências" }),
        f("b", "alto", "DEBUG=True vaza o stacktrace em produção", "config/settings.py:12", "semgrep", "CWE-489", ["critico"]),
        f("c", "medio", "Login sem limite de tentativas", "POST /api/login", "exemplo", "CWE-307", ["bot"]),
        f("d", "info", "Porta 8000 escuta só na tua máquina (ok)", "porta 8000/tcp", "portas", "INVENTARIO", []),
      ],
      lgpd: lg, resolvidos: [], chave: "demo",
      meta: { alvo: "prévia no navegador (dados de exemplo)", rodaram: ["demo"], pulados: [["semgrep", "não instalado"]], avisos: [], fundidos: 0, nota_ia: "" },
    });
    let pendente = null, t0 = 0, cancelou = false;
    return {
      inicio: () => ({ versao: "prévia", modelo: "llama3.1:8b", auditoria: null, ia: null, ocupado: null, lgpd: lg, aviso_lgpd: "Confirmação manual: o Argos não verifica estes itens sozinho." }),
      auditar: () => { pendente = "auditoria"; t0 = Date.now(); return { ok: true }; },
      testar_ia: () => { pendente = "ia"; t0 = Date.now(); return { ok: true }; },
      status: (desde) => {
        const roteiro = [[0.1, "trilha", "trilha codigo: código parado"], [0.4, "inicio", "gitleaks: começando…"],
          [1.2, "ok", "gitleaks: 1 achado(s) em 0.8s"], [1.3, "pulado", "pip-audit: não instalado, pulando"],
          [1.5, "inicio", "semgrep: começando…"], [3.2, "ok", "semgrep: 2 achado(s) em 1.7s"]];
        const dt = (Date.now() - t0) / 1000;
        const vis = pendente || cancelou ? roteiro.filter(r => r[0] <= dt) : [];
        const log = vis.slice(desde || 0).map(([t, tipo, msg]) => ({ t, tipo, msg }));
        const pos = Math.max(desde || 0, vis.length);
        if (cancelou) { cancelou = false; pendente = null; return { ocupado: null, conj: "auditoria", cancelado: true, log, pos }; }
        if (!pendente) return { ocupado: null, log: [], pos: desde || 0 };
        if (dt < 3.5) return { ocupado: pendente, log, pos };
        const c = pendente; pendente = null;
        return { ocupado: null, conj: c, dados: demo(), log, pos };
      },
      cancelar: () => { cancelou = !!pendente; return cancelou ? { ok: true } : { erro: "Nada rodando." }; },
      alternar: (c, fp) => { const x = app.conj[c].findings.find(y => y.fp === fp); x.feito = !x.feito; const fe = app.conj[c].findings.filter(y => y.feito).length; return { feito: x.feito, feitos: fe, total: app.conj[c].placar.total }; },
      alternar_lgpd: n => ({ feito: !lg[n].feito }),
      aceitar: () => ({ ok: true, ate: "daqui a 30 dias" }),
      exemplo_prompt: () => "Você é a Lumi, assistente de uma comunidade de desenvolvimento de jogos.",
      gerar_canario: () => "ARGOS-CANARIO-PREVIA1",
      escolher: () => "",
      abrir_texto: () => ({ texto: "" }),
      exportar_html: () => ({ erro: "Na prévia do navegador não dá pra exportar." }),
      texto_ia: () => (app.conj.auditoria ? { texto: "# Argos: brechas pra corrigir\n\n(prévia)" } : { erro: "Rode uma auditoria antes de exportar." }),
      exportar_ia: () => ({ erro: "Na prévia do navegador não dá pra salvar arquivo." }),
    };
  })();

  // gancho pra testes automatizados e depuração (não expõe nada do sistema)
  window.ArgosApp = { humor: h => humor(h), trocarView, estado: () => app };

  // ------------------------------------------------------------ partida

  let iniciado = false;
  const comecar = () => { if (!iniciado) { iniciado = true; iniciar(); } };
  window.addEventListener("pywebviewready", comecar);
  window.addEventListener("DOMContentLoaded", () => setTimeout(() => {
    if (!(window.pywebview && window.pywebview.api)) comecar();
  }, 900));
})();
