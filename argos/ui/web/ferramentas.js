/* Argos — cena da ferramenta ativa (Fase C).
 *
 * Enquanto a varredura roda, mostra no palco (sob o olho que observa) uma
 * mini-animação do que o scanner está fazendo: lupa do gitleaks caçando
 * segredo, feixe varrendo código, pacotes sendo farejados, radar de portas,
 * e o prédio apanhando no modo ataque. É SVG + CSS puro (sem imagem).
 *
 * API:  const cena = ArgosFerramentas.montar(palcoEl)
 *       cena.ativar("segredos", "gitleaks · caçando segredos")
 *       cena.ocioso()
 *
 * O app decide a cena pelo NOME do scanner que começou (linha tipo "inicio").
 */
(function () {
  "use strict";

  // nome do scanner (ex.: "codigo:gitleaks", "trafego:tshark", "ataque") -> cena + rótulo
  const MAPA = [
    [/gitleaks|segredo/i, "segredos", "caçando segredos no código"],
    [/semgrep|bandit|permiss|config|django|codigo:config/i, "codigo", "varrendo o código"],
    [/pip-audit|npm|osv|trivy|depend/i, "dependencias", "conferindo dependências"],
    [/tshark|trafego|tráfego|pacote|wireshark/i, "pacotes", "farejando pacotes"],
    [/nmap|porta|nativo/i, "portas", "varrendo portas"],
    [/web|cabeçalho|header|cors|cookie/i, "web", "testando o servidor web"],
    [/ataqu|atac|idor|csrf|xss|injeç|injec|carga|força|brute/i, "ataque", "atacando o alvo local"],
    [/ia|ollama|prompt/i, "ia", "testando a IA"],
  ];

  function cenaDoNome(nome) {
    const n = String(nome || "");
    for (const [re, cena, rotulo] of MAPA) if (re.test(n)) return { cena, rotulo };
    return { cena: "generico", rotulo: "trabalhando" };
  }

  // --- cenas (SVG como string; as animações vivem no estilo.css) ---
  const SVG = {
    segredos: `
      <svg viewBox="0 0 220 120" class="cena-svg" aria-hidden="true">
        <g class="doc">
          <rect x="24" y="16" width="120" height="88" rx="8"/>
          <line x1="40" y1="36" x2="128" y2="36"/><line x1="40" y1="52" x2="112" y2="52"/>
          <line x1="40" y1="68" x2="128" y2="68"/><line x1="40" y1="84" x2="96" y2="84"/>
        </g>
        <g class="chave"><circle cx="112" cy="52" r="6"/><rect x="109" y="52" width="6" height="12"/></g>
        <g class="lupa">
          <circle cx="0" cy="0" r="20"/><line x1="15" y1="15" x2="30" y2="30"/>
        </g>
      </svg>`,
    codigo: `
      <svg viewBox="0 0 220 120" class="cena-svg" aria-hidden="true">
        <g class="linhas">
          ${Array.from({ length: 7 }, (_, i) =>
            `<rect x="34" y="${20 + i * 12}" width="${60 + ((i * 37) % 110)}" height="5" rx="2.5"/>`).join("")}
        </g>
        <rect class="feixe" x="28" y="16" width="164" height="7" rx="3.5"/>
      </svg>`,
    dependencias: `
      <svg viewBox="0 0 220 120" class="cena-svg" aria-hidden="true">
        <g class="pacotes">
          <g class="pk pk1"><rect x="30" y="64" width="34" height="34" rx="5"/><path d="M30 74h34"/><path d="M47 64v34"/></g>
          <g class="pk pk2"><rect x="76" y="50" width="34" height="34" rx="5"/><path d="M76 60h34"/><path d="M93 50v34"/></g>
          <g class="pk pk3 ruim"><rect x="122" y="64" width="34" height="34" rx="5"/><path d="M122 74h34"/><path d="M139 64v34"/></g>
          <g class="pk pk4"><rect x="168" y="56" width="22" height="42" rx="5"/></g>
        </g>
        <g class="selo"><path d="M-9 0l6 6 11-13"/></g>
      </svg>`,
    pacotes: `
      <svg viewBox="0 0 220 120" class="cena-svg" aria-hidden="true">
        <line class="fio" x1="10" y1="60" x2="150" y2="60"/>
        <g class="funil"><path d="M150 40 L186 28 186 92 150 80 Z"/><circle cx="196" cy="60" r="12"/><line x1="205" y1="69" x2="214" y2="78"/></g>
        <g class="pacote p1"><rect x="0" y="54" width="14" height="12" rx="2"/></g>
        <g class="pacote p2"><rect x="0" y="54" width="14" height="12" rx="2"/></g>
        <g class="pacote p3 sensivel"><rect x="0" y="54" width="14" height="12" rx="2"/></g>
      </svg>`,
    portas: `
      <svg viewBox="0 0 220 120" class="cena-svg" aria-hidden="true">
        <g class="radar">
          <circle cx="110" cy="60" r="46"/><circle cx="110" cy="60" r="30"/><circle cx="110" cy="60" r="14"/>
          <g class="varredura"><path d="M110 60 L110 12 A48 48 0 0 1 150 40 Z"/></g>
          <circle class="blip b1" cx="138" cy="44" r="3.5"/>
          <circle class="blip b2" cx="86" cy="80" r="3.5"/>
          <circle class="blip b3 aberta" cx="128" cy="84" r="4.5"/>
        </g>
      </svg>`,
    web: `
      <svg viewBox="0 0 220 120" class="cena-svg" aria-hidden="true">
        <g class="navegador">
          <rect x="40" y="20" width="140" height="84" rx="8"/>
          <line x1="40" y1="40" x2="180" y2="40"/>
          <circle cx="52" cy="30" r="3"/><circle cx="62" cy="30" r="3"/><circle cx="72" cy="30" r="3"/>
          <g class="headers">
            <rect class="h h1" x="54" y="54" width="112" height="8" rx="4"/>
            <rect class="h h2" x="54" y="70" width="90" height="8" rx="4"/>
            <rect class="h h3 falta" x="54" y="86" width="104" height="8" rx="4"/>
          </g>
        </g>
      </svg>`,
    ataque: `
      <svg viewBox="0 0 220 120" class="cena-svg cena-ataque" aria-hidden="true">
        <line x1="12" y1="107" x2="208" y2="107" class="chao"/>
        <!-- lançador (atacante) -->
        <g class="lancador"><rect x="14" y="94" width="28" height="13" rx="2"/><path d="M34 94 l7 -9"/></g>
        <!-- alvo -->
        <g class="predio">
          <rect x="150" y="58" width="46" height="49" rx="3"/>
          ${Array.from({ length: 6 }, (_, i) =>
            `<rect class="jan j${i}" x="${157 + (i % 2) * 18}" y="${66 + Math.floor(i / 2) * 13}" width="10" height="9" rx="1.5"/>`).join("")}
          <rect class="escudo" x="146" y="54" width="54" height="57" rx="6"/>
        </g>
        <!-- trajetória fantasma (∩) -->
        <path class="trilha" d="M32 99 Q 112 -30 173 66"/>
        <!-- mísseis no arco -->
        <g class="missil m1"><path class="rastro" d="M-6 0 L-18 0"/><path class="corpo" d="M-7 0 L5 0"/><path class="ponta" d="M5 -3 L11 0 L5 3 Z"/></g>
        <g class="missil m2"><path class="rastro" d="M-6 0 L-18 0"/><path class="corpo" d="M-7 0 L5 0"/><path class="ponta" d="M5 -3 L11 0 L5 3 Z"/></g>
        <g class="missil m3"><path class="rastro" d="M-6 0 L-18 0"/><path class="corpo" d="M-7 0 L5 0"/><path class="ponta" d="M5 -3 L11 0 L5 3 Z"/></g>
        <!-- impacto no prédio -->
        <g class="impacto"><circle r="3"/><path class="estilhaco" d="M0 -11 V-5 M0 11 V5 M-11 0 H-5 M11 0 H5 M-8 -8 L-4 -4 M8 8 L4 4 M8 -8 L4 -4 M-8 8 L-4 4"/></g>
      </svg>`,
    ia: `
      <svg viewBox="0 0 220 120" class="cena-svg" aria-hidden="true">
        <g class="cerebro">
          <circle cx="110" cy="58" r="30"/>
          <path d="M110 30 v56 M86 44 h48 M88 72 h44"/>
        </g>
        <g class="injecao"><rect x="18" y="52" width="40" height="14" rx="3"/><path d="M58 59 h22"/></g>
      </svg>`,
    generico: `
      <svg viewBox="0 0 220 120" class="cena-svg" aria-hidden="true">
        <circle class="anel a1" cx="110" cy="60" r="16"/>
        <circle class="anel a2" cx="110" cy="60" r="30"/>
        <circle class="anel a3" cx="110" cy="60" r="44"/>
      </svg>`,
  };

  // glifos das ferramentas que orbitam o olho (viewBox 0 0 24 24)
  const ORBES = [
    ["segredos", `<circle cx="10" cy="10" r="6"/><line x1="15" y1="15" x2="21" y2="21"/>`],
    ["codigo", `<path d="M9 8l-5 4 5 4"/><path d="M15 8l5 4-5 4"/>`],
    ["dependencias", `<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M4 7.5l8 4.5 8-4.5M12 12v9"/>`],
    ["pacotes", `<path d="M4 9a12 12 0 0 1 16 0"/><path d="M7 12a8 8 0 0 1 10 0"/><circle cx="12" cy="16" r="1.4"/>`],
    ["portas", `<circle cx="12" cy="12" r="8"/><path d="M12 12l6-3"/><circle cx="12" cy="12" r="1.5"/>`],
    ["web", `<circle cx="12" cy="12" r="8"/><path d="M4 12h16M12 4c3 3 3 13 0 16M12 4c-3 3-3 13 0 16"/>`],
    ["ataque", `<path d="M12 3c4 2 5 7 4 11l-4 4-4-4c-1-4 0-9 4-11z"/><circle cx="12" cy="10" r="1.6"/><path d="M8 17l-2 4 4-2M16 17l2 4-4-2"/>`],
    ["ia", `<rect x="7" y="7" width="10" height="10" rx="2"/><path d="M12 3v4M12 17v4M3 12h4M17 12h4"/>`],
  ];

  function montar(palco) {
    if (!palco) return { ativar() {}, ocioso() {} };

    // glow ao fundo + anel de ferramentas orbitando (só aparecem no estado "vigiando")
    const glow = document.createElement("div");
    glow.className = "palco-glow";
    glow.setAttribute("aria-hidden", "true");
    palco.appendChild(glow);

    const orbita = document.createElement("div");
    orbita.className = "palco-orbita";
    orbita.setAttribute("aria-hidden", "true");
    orbita.innerHTML = `<div class="orbita-anel">` + ORBES.map(([k], i) =>
      `<div class="orbe" data-k="${k}" style="--a:${(i / ORBES.length) * 360}deg">` +
      `<div class="anti"><span class="ico"><svg viewBox="0 0 24 24">${ORBES[i][1]}</svg></span></div></div>`
    ).join("") + `</div>`;
    palco.appendChild(orbita);
    const orbes = {};
    orbita.querySelectorAll(".orbe").forEach(o => { orbes[o.dataset.k] = o; });

    const caixa = document.createElement("div");
    caixa.className = "palco-ferramenta";
    caixa.setAttribute("aria-hidden", "true");
    caixa.innerHTML = `<div class="cena-quadro"></div><div class="cena-rotulo"><i></i><span></span></div>`;
    palco.appendChild(caixa);
    const quadro = caixa.querySelector(".cena-quadro");
    const rotuloTxt = caixa.querySelector(".cena-rotulo span");
    let atual = null;

    function acender(cena) {
      for (const k in orbes) orbes[k].classList.toggle("on", k === cena);
    }

    return {
      ativar(nome) {
        const { cena, rotulo } = cenaDoNome(nome);
        rotuloTxt.textContent = (String(nome).split(":").pop() || cena) + " · " + rotulo;
        caixa.dataset.cena = cena;
        caixa.classList.toggle("atacando", cena === "ataque");
        if (cena !== atual) {           // só re-injeta o SVG quando a cena muda (reinicia a animação)
          quadro.innerHTML = SVG[cena] || SVG.generico;
          atual = cena;
        }
        acender(cena);
        caixa.classList.add("ativa");
      },
      ocioso() {
        caixa.classList.remove("ativa", "atacando");
        quadro.innerHTML = "";
        acender(null);
        atual = null;
      },
    };
  }

  window.ArgosFerramentas = { montar, cenaDoNome };
})();
