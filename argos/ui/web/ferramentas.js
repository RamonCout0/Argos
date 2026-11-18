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
        <line x1="20" y1="106" x2="200" y2="106" class="chao"/>
        <g class="predio">
          <rect x="84" y="40" width="54" height="66" rx="3"/>
          ${Array.from({ length: 9 }, (_, i) =>
            `<rect class="jan j${i}" x="${92 + (i % 3) * 15}" y="${48 + Math.floor(i / 3) * 16}" width="9" height="9" rx="1.5"/>`).join("")}
          <rect class="escudo" x="80" y="36" width="62" height="74" rx="6"/>
        </g>
        <g class="tiros">
          <circle class="tiro t1" r="3.5"/><circle class="tiro t2" r="3.5"/><circle class="tiro t3" r="3.5"/>
        </g>
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

  function montar(palco) {
    if (!palco) return { ativar() {}, ocioso() {} };
    const caixa = document.createElement("div");
    caixa.className = "palco-ferramenta";
    caixa.setAttribute("aria-hidden", "true");
    caixa.innerHTML = `<div class="cena-quadro"></div><div class="cena-rotulo"><i></i><span></span></div>`;
    palco.appendChild(caixa);
    const quadro = caixa.querySelector(".cena-quadro");
    const rotuloTxt = caixa.querySelector(".cena-rotulo span");
    let atual = null;

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
        caixa.classList.add("ativa");
      },
      ocioso() {
        caixa.classList.remove("ativa", "atacando");
        quadro.innerHTML = "";
        atual = null;
      },
    };
  }

  window.ArgosFerramentas = { montar, cenaDoNome };
})();
