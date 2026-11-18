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

  // ferramentas que orbitam o olho. Onde a ferramenta tem logo de marca (simple-icons,
  // viewBox 0 0 24 24, uso nominativo = indicar a ferramenta que roda), usamos o logo
  // real; onde não há (nmap, gitleaks, semgrep), um glifo original. cena = liga ao palco;
  // re = casa o nome do scanner em andamento pra acender o orbe certo.
  const FERRAS = [
    { id:"gitleaks", rot:"gitleaks", cena:"segredos", re:/gitleaks|segredo/i, ico:"<svg viewBox=\"0 0 24 24\"><circle cx=\"10\" cy=\"10\" r=\"6\"/><line x1=\"15\" y1=\"15\" x2=\"21\" y2=\"21\"/></svg>" },
    { id:"semgrep", rot:"semgrep", cena:"codigo", re:/semgrep|bandit|permiss|config|django/i, ico:"<svg viewBox=\"0 0 24 24\"><circle cx=\"6.5\" cy=\"15\" r=\"3\"/><circle cx=\"12\" cy=\"6.5\" r=\"3\"/><circle cx=\"17.5\" cy=\"15\" r=\"3\"/></svg>" },
    { id:"pypi", rot:"pip-audit", cena:"dependencias", re:/pip-audit|pip_audit/i, ico:"<svg viewBox=\"0 0 24 24\" class=\"marca\"><path d=\"M23.922 13.58v3.912L20.55 18.72l-.078.055.052.037 3.45-1.256.026-.036v-3.997l-.053-.036-.025.092z M23.621 5.618l-3.04 1.107v3.912l3.339-1.215V5.509zM23.92 13.457V9.544l-3.336 1.215v3.913zM20.47 14.71V10.8L17.17 12v3.913zM17.034 19.996v-3.912l-3.313 1.206v3.912zM17.17 16.057v3.868l3.314-1.206V14.85l-3.314 1.206zm2.093 1.882c-.367.134-.663-.074-.663-.463s.296-.814.663-.947c.365-.133.662.075.662.464s-.297.814-.662.946z M13.225 9.315l.365-.132-3.285-1.197-3.323 1.21.102.037 3.184 1.16zM20.507 10.664V6.751L17.17 7.965v3.913zM17.058 11.918V8.005l-3.302 1.202v3.912zM13.643 9.246l-3.336 1.215v3.913l3.336-1.215zM6.907 13.165l3.322 1.209v-3.913L6.907 9.252z M10.34 7.873l3.281 1.193V5.198l-3.28-1.193zM20.507 2.715L17.19 3.922v3.913l3.317-1.207zM16.95 3.903L13.724 2.73l-3.269 1.19 3.225 1.174zM15.365 4.606l-1.624.592v3.868l3.317-1.207V3.991l-1.693.615zm-.391 2.778c-.367.134-.662-.074-.662-.464s.295-.813.662-.946c.366-.133.663.074.663.464s-.297.813-.663.946z M10.229 18.41v-3.914l-3.322-1.209V17.2zM13.678 17.182v-3.913l-3.371 1.227v3.913z M13.756 17.154l3.3-1.2V12.04l-3.3 1.2zM13.678 21.217l-3.371 1.227v-3.912h-.078v3.912l-3.322-1.209v-3.913l-.053-.058-.025-.06-3.336-1.21v-3.948l.034.013 3.287 1.196.015-.078-3.261-1.187 3.26-1.187v-.109L3.876 9.62l-.307-.112 3.26-1.188v.877l.079-.055V6.769l3.257 1.185.058-.061L7.084 6.75l-.102-.037 3.24-1.179v-.083L6.854 6.677v.018l-.025.018v1.523L3.44 9.47v.02l-.025.017v4.007l-3.39 1.233v.019L0 14.784v3.995l.025.037 3.4 1.237.008-.006.007.01 3.4 1.238.008-.006.006.01 3.4 1.237.014-.009.012.01 3.45-1.256.026-.037-.078-.027zM3.493 9.563l3.257 1.185-3.257 1.187V9.562zM3.4 19.96L.078 18.752v-3.913l2.361.86.96.349v3.913zm.015-3.99L.335 14.85l-.182-.066 3.262-1.187v2.374zm3.399 5.231l-3.321-1.209v-3.912l3.321 1.209v3.912zM23.791 5.434l-3.21-1.17v2.338zM20.387 2.643l-3.24-1.18-3.27 1.19 3.247 1.182z\" fill=\"#3775A9\"/></svg>" },
    { id:"npm", rot:"npm audit", cena:"dependencias", re:/npm/i, ico:"<svg viewBox=\"0 0 24 24\" class=\"marca\"><path d=\"M1.763 0C.786 0 0 .786 0 1.763v20.474C0 23.214.786 24 1.763 24h20.474c.977 0 1.763-.786 1.763-1.763V1.763C24 .786 23.214 0 22.237 0zM5.13 5.323l13.837.019-.009 13.836h-3.464l.01-10.382h-3.456L12.04 19.17H5.113z\" fill=\"#CB3837\"/></svg>" },
    { id:"trivy", rot:"Trivy", cena:"dependencias", re:/trivy/i, ico:"<svg viewBox=\"0 0 24 24\" class=\"marca\"><path d=\"M4.375 7.311 1.962 5.918a.1.1 0 0 1 0-.174L11.828.047a.343.343 0 0 1 .344 0l9.864 5.696a.1.1 0 0 1 0 .175L19.624 7.31a.962.962 0 0 1-.052-.074c-.914-1.478-2.124-2.592-3.596-3.31-4.088-1.994-9.164-.505-11.6 3.385ZM12.262 23.899v-3.14c5.693-2.087 9.01-7.766 7.588-12.985l2.436-1.42a.1.1 0 0 1 .151.088v11.645a.1.1 0 0 1-.05.087l-9.973 5.812a.1.1 0 0 1-.152-.087Zm-.559-3.141v3.14a.1.1 0 0 1-.151.086l-9.933-5.81a.114.114 0 0 1-.056-.099V6.436a.1.1 0 0 1 .15-.087l2.44 1.41c-1.455 5.307 1.846 10.993 7.55 13ZM7.013 8.834 4.807 7.561c2.306-3.665 7.094-5.066 10.95-3.186 1.385.676 2.526 1.727 3.39 3.124l.04.062-2.195 1.268a5.57 5.57 0 0 0-2.429-2.307c-2.603-1.27-5.901-.253-7.552 2.311Zm9.337 5.2c.813-1.371 1.088-2.99.798-4.685l2.255-1.314c1.245 4.86-1.864 10.169-7.14 12.192v-3.072c1.86-.67 3.272-1.747 4.087-3.12ZM4.6 8.018l2.27 1.31c-.225 1.571.112 3.204.951 4.606.919 1.536 2.225 2.629 3.881 3.25v3.045C6.327 18.25 3.297 13.042 4.601 8.017Zm5.303 2.486-2.459-1.42c1.52-2.34 4.53-3.268 6.9-2.112a5.075 5.075 0 0 1 2.216 2.108l-2.471 1.427a2.311 2.311 0 0 0-2.03-1.195c-.825 0-1.645.43-2.156 1.192Zm4.338.522 2.443-1.408c.22 1.51-.043 2.945-.765 4.162-.735 1.238-1.998 2.224-3.658 2.856v-2.631c1.25-.691 1.968-1.771 1.98-2.979ZM8.25 13.676A6.576 6.576 0 0 1 7.34 9.6l2.446 1.412c-.016 1.271.73 2.437 1.917 2.997v2.624a6.977 6.977 0 0 1-3.453-2.956Zm3.853-.148-.137.073-.157-.075c-1.023-.504-1.524-1.606-1.557-2.417a1.99 1.99 0 0 1 .004-.23 2.153 2.153 0 0 1 1.163-.957c.508-.178 1.034-.153 1.444.071.6.327.84.797.86.86.008.156.004.253.004.256-.038.981-.63 1.863-1.624 2.419Z\" fill=\"#dfe8ff\"/></svg>" },
    { id:"osv", rot:"OSV (Google)", cena:"dependencias", re:/osv/i, ico:"<svg viewBox=\"0 0 24 24\" class=\"marca\"><path d=\"M12.48 10.92v3.28h7.84c-.24 1.84-.853 3.187-1.787 4.133-1.147 1.147-2.933 2.4-6.053 2.4-4.827 0-8.6-3.893-8.6-8.72s3.773-8.72 8.6-8.72c2.6 0 4.507 1.027 5.907 2.347l2.307-2.307C18.747 1.44 16.133 0 12.48 0 5.867 0 .307 5.387.307 12s5.56 12 12.173 12c3.573 0 6.267-1.173 8.373-3.36 2.16-2.16 2.84-5.213 2.84-7.667 0-.76-.053-1.467-.173-2.053H12.48z\" fill=\"#4285F4\"/></svg>" },
    { id:"wireshark", rot:"Wireshark", cena:"pacotes", re:/tshark|trafego|tráfego|wireshark|pacote/i, ico:"<svg viewBox=\"0 0 24 24\" class=\"marca\"><path d=\"m2.95 0c-1.62 0-2.95 1.32-2.95 2.95v18.1c0 1.63 1.32 2.95 2.95 2.95h18.1c1.62 0 2.95-1.32 2.95-2.95v-18.1c-.00024-1.63-1.32-2.95-2.95-2.95zm0 1.09h18.1c1.04 0 1.85.818 1.85 1.86v14h-5.27c-.335-.796-2.57-6.47.283-10.9a.516.517 0 0 0-.443-.794c-5.24.0827-8.2 3.19-9.74 6.21-1.35 2.64-1.63 4.91-1.69 5.53h-4.95v-14c0-1.04.817-1.86 1.85-1.86zm13.6 5.24c-2.62 5.24.248 11.4.248 11.4a.516.517 0 0 0 .469.301h5.62v3.05c0 1.04-.817 1.86-1.85 1.86h-18.1c-1.04 0-1.85-.818-1.85-1.86v-3.05h5.39a.516.517 0 0 0 .514-.477s.226-2.8 1.66-5.62c1.34-2.62 3.67-5.17 7.91-5.57z\" fill=\"#1679A7\"/></svg>" },
    { id:"nmap", rot:"nmap", cena:"portas", re:/nmap|porta|nativo/i, ico:"<svg viewBox=\"0 0 24 24\"><circle cx=\"12\" cy=\"12\" r=\"8\"/><path d=\"M12 12l6-3\"/><circle cx=\"12\" cy=\"12\" r=\"1.5\"/></svg>" },
    { id:"owasp", rot:"OWASP", cena:"web", re:/web|cors|cookie|header|cabeç/i, ico:"<svg viewBox=\"0 0 24 24\" class=\"marca\"><path d=\"M15.897 20.503c-.384 0-1.782-2.489-1.97-3.198-.393-1.486-.308-2.114-.285-2.314.072-.613.667-.92.703-1.748.01-.256.14-1.535.243-2.534a1.723 1.723 0 0 1-.733-.343c.676.908-.32 1.995-1.767 3.443-1.536 1.536-4.945 2.961-4.945 2.961s1.425-3.41 2.961-4.945c1.13-1.129 2.04-1.983 2.816-1.983.22 0 .427.067.627.216a1.722 1.722 0 0 1-.343-.733c-.999.103-2.278.232-2.534.244-.829.036-1.135.63-1.747.702-.07.008-.194.024-.388.024-.36 0-.963-.054-1.926-.31-.772-.203-3.648-1.84-3.14-2.045.26-.105 1.087-.176 2.175-.176 1.047 0 2.337.066 3.596.23 1.57.205 3.01.463 3.992.656.016-.053.035-.104.058-.154l-1.004-.48s-.8-.92-.715-.984a.02.02 0 0 1 .012-.003c.126 0 .767.733.829.816l.605.202-.284-.249s-.388-1.438-.287-1.472h.004c.106 0 .459 1.25.489 1.34.07.06.303.152.596.32l-.308-.79s.14-1.305.243-1.305h.003c.105.021-.02 1.089-.047 1.221l.51.783a1.31 1.31 0 0 1 .463-.082c.184 0 .374.036.558.107-.236-.502-.218-1.025.095-1.338a.84.84 0 0 1 .353-.209.462.462 0 0 1 .457-.383c.127 0 .254.05.352.148a.497.497 0 0 1 .147.335c.151-.311.329-.73.317-.867-.03-.307-.386-.852-.39-.857a.076.076 0 0 1 .064-.119c.025 0 .05.012.064.035.016.023.381.582.414.927.018.198-.21.696-.333.95a2.227 2.227 0 0 1 .873.874c.245-.12.715-.334.927-.334l.024.001c.345.033.904.399.927.414a.076.076 0 0 1-.084.128c-.005-.004-.55-.36-.857-.39h-.015c-.15 0-.552.171-.852.317.12.004.242.053.335.147a.482.482 0 0 1 .012.681.459.459 0 0 1-.247.128.845.845 0 0 1-.21.354.924.924 0 0 1-.67.255c-.212 0-.441-.055-.667-.16.132.343.142.708.025 1.02l.783.51c.095-.019.666-.088.993-.088.13 0 .222.011.228.04.02.106-1.305.247-1.305.247l-.79-.308c.168.293.26.527.32.596.091.03 1.374.392 1.34.493-.004.012-.026.017-.063.017-.283 0-1.41-.304-1.41-.304l-.248-.284.202.605c.087.065.876.755.813.841-.004.005-.009.007-.016.007-.139 0-.967-.722-.967-.722l-.481-1.004a1.18 1.18 0 0 1-.154.058c.193.982.451 2.422.656 3.992.335 2.569.26 5.261.054 5.77-.016.041-.042.06-.076.06M12 24C5.373 24 0 18.627 0 12S5.373 0 12 0s12 5.373 12 12-5.373 12-12 12m0-22.153C6.393 1.847 1.847 6.393 1.847 12S6.393 22.153 12 22.153 22.153 17.607 22.153 12 17.607 1.847 12 1.847Z\" fill=\"#dfe8ff\"/></svg>" },
    { id:"ollama", rot:"Ollama", cena:"ia", re:/ollama|ia|prompt/i, ico:"<svg viewBox=\"0 0 24 24\" class=\"marca\"><path d=\"M16.361 10.26a.894.894 0 0 0-.558.47l-.072.148.001.207c0 .193.004.217.059.353.076.193.152.312.291.448.24.238.51.3.872.205a.86.86 0 0 0 .517-.436.752.752 0 0 0 .08-.498c-.064-.453-.33-.782-.724-.897a1.06 1.06 0 0 0-.466 0zm-9.203.005c-.305.096-.533.32-.65.639a1.187 1.187 0 0 0-.06.52c.057.309.31.59.598.667.362.095.632.033.872-.205.14-.136.215-.255.291-.448.055-.136.059-.16.059-.353l.001-.207-.072-.148a.894.894 0 0 0-.565-.472 1.02 1.02 0 0 0-.474.007Zm4.184 2c-.131.071-.223.25-.195.383.031.143.157.288.353.407.105.063.112.072.117.136.004.038-.01.146-.029.243-.02.094-.036.194-.036.222.002.074.07.195.143.253.064.052.076.054.255.059.164.005.198.001.264-.03.169-.082.212-.234.15-.525-.052-.243-.042-.28.087-.355.137-.08.281-.219.324-.314a.365.365 0 0 0-.175-.48.394.394 0 0 0-.181-.033c-.126 0-.207.03-.355.124l-.085.053-.053-.032c-.219-.13-.259-.145-.391-.143a.396.396 0 0 0-.193.032zm.39-2.195c-.373.036-.475.05-.654.086-.291.06-.68.195-.951.328-.94.46-1.589 1.226-1.787 2.114-.04.176-.045.234-.045.53 0 .294.005.357.043.524.264 1.16 1.332 2.017 2.714 2.173.3.033 1.596.033 1.896 0 1.11-.125 2.064-.727 2.493-1.571.114-.226.169-.372.22-.602.039-.167.044-.23.044-.523 0-.297-.005-.355-.045-.531-.288-1.29-1.539-2.304-3.072-2.497a6.873 6.873 0 0 0-.855-.031zm.645.937a3.283 3.283 0 0 1 1.44.514c.223.148.537.458.671.662.166.251.26.508.303.82.02.143.01.251-.043.482-.08.345-.332.705-.672.957a3.115 3.115 0 0 1-.689.348c-.382.122-.632.144-1.525.138-.582-.006-.686-.01-.853-.042-.57-.107-1.022-.334-1.35-.68-.264-.28-.385-.535-.45-.946-.03-.192.025-.509.137-.776.136-.326.488-.73.836-.963.403-.269.934-.46 1.422-.512.187-.02.586-.02.773-.002zm-5.503-11a1.653 1.653 0 0 0-.683.298C5.617.74 5.173 1.666 4.985 2.819c-.07.436-.119 1.04-.119 1.503 0 .544.064 1.24.155 1.721.02.107.031.202.023.208a8.12 8.12 0 0 1-.187.152 5.324 5.324 0 0 0-.949 1.02 5.49 5.49 0 0 0-.94 2.339 6.625 6.625 0 0 0-.023 1.357c.091.78.325 1.438.727 2.04l.13.195-.037.064c-.269.452-.498 1.105-.605 1.732-.084.496-.095.629-.095 1.294 0 .67.009.803.088 1.266.095.555.288 1.143.503 1.534.071.128.243.393.264.407.007.003-.014.067-.046.141a7.405 7.405 0 0 0-.548 1.873c-.062.417-.071.552-.071.991 0 .56.031.832.148 1.279L3.42 24h1.478l-.05-.091c-.297-.552-.325-1.575-.068-2.597.117-.472.25-.819.498-1.296l.148-.29v-.177c0-.165-.003-.184-.057-.293a.915.915 0 0 0-.194-.25 1.74 1.74 0 0 1-.385-.543c-.424-.92-.506-2.286-.208-3.451.124-.486.329-.918.544-1.154a.787.787 0 0 0 .223-.531c0-.195-.07-.355-.224-.522a3.136 3.136 0 0 1-.817-1.729c-.14-.96.114-2.005.69-2.834.563-.814 1.353-1.336 2.237-1.475.199-.033.57-.028.776.01.226.04.367.028.512-.041.179-.085.268-.19.374-.431.093-.215.165-.333.36-.576.234-.29.46-.489.822-.729.413-.27.884-.467 1.352-.561.17-.035.25-.04.569-.04.319 0 .398.005.569.04a4.07 4.07 0 0 1 1.914.997c.117.109.398.457.488.602.034.057.095.177.132.267.105.241.195.346.374.43.14.068.286.082.503.045.343-.058.607-.053.943.016 1.144.23 2.14 1.173 2.581 2.437.385 1.108.276 2.267-.296 3.153-.097.15-.193.27-.333.419-.301.322-.301.722-.001 1.053.493.539.801 1.866.708 3.036-.062.772-.26 1.463-.533 1.854a2.096 2.096 0 0 1-.224.258.916.916 0 0 0-.194.25c-.054.109-.057.128-.057.293v.178l.148.29c.248.476.38.823.498 1.295.253 1.008.231 2.01-.059 2.581a.845.845 0 0 0-.044.098c0 .006.329.009.732.009h.73l.02-.074.036-.134c.019-.076.057-.3.088-.516.029-.217.029-1.016 0-1.258-.11-.875-.295-1.57-.597-2.226-.032-.074-.053-.138-.046-.141.008-.005.057-.074.108-.152.376-.569.607-1.284.724-2.228.031-.26.031-1.378 0-1.628-.083-.645-.182-1.082-.348-1.525a6.083 6.083 0 0 0-.329-.7l-.038-.064.131-.194c.402-.604.636-1.262.727-2.04a6.625 6.625 0 0 0-.024-1.358 5.512 5.512 0 0 0-.939-2.339 5.325 5.325 0 0 0-.95-1.02 8.097 8.097 0 0 1-.186-.152.692.692 0 0 1 .023-.208c.208-1.087.201-2.443-.017-3.503-.19-.924-.535-1.658-.98-2.082-.354-.338-.716-.482-1.15-.455-.996.059-1.8 1.205-2.116 3.01a6.805 6.805 0 0 0-.097.726c0 .036-.007.066-.015.066a.96.96 0 0 1-.149-.078A4.857 4.857 0 0 0 12 3.03c-.832 0-1.687.243-2.456.698a.958.958 0 0 1-.148.078c-.008 0-.015-.03-.015-.066a6.71 6.71 0 0 0-.097-.725C8.997 1.392 8.337.319 7.46.048a2.096 2.096 0 0 0-.585-.041Zm.293 1.402c.248.197.523.759.682 1.388.03.113.06.244.069.292.007.047.026.152.041.233.067.365.098.76.102 1.24l.002.475-.12.175-.118.178h-.278c-.324 0-.646.041-.954.124l-.238.06c-.033.007-.038-.003-.057-.144a8.438 8.438 0 0 1 .016-2.323c.124-.788.413-1.501.696-1.711.067-.05.079-.049.157.013zm9.825-.012c.17.126.358.46.498.888.28.854.36 2.028.212 3.145-.019.14-.024.151-.057.144l-.238-.06a3.693 3.693 0 0 0-.954-.124h-.278l-.119-.178-.119-.175.002-.474c.004-.669.066-1.19.214-1.772.157-.623.434-1.185.68-1.382.078-.062.09-.063.159-.012z\" fill=\"#dfe8ff\"/></svg>" },
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
    orbita.innerHTML = `<div class="orbita-anel">` + FERRAS.map((f, i) =>
      `<div class="orbe" data-id="${f.id}" style="--a:${(i / FERRAS.length) * 360}deg" title="${f.rot}">` +
      `<div class="anti"><span class="ico">${f.ico}</span></div></div>`
    ).join("") + `</div>`;
    palco.appendChild(orbita);
    const orbes = {};
    orbita.querySelectorAll(".orbe").forEach(o => { orbes[o.dataset.id] = o; });

    const caixa = document.createElement("div");
    caixa.className = "palco-ferramenta";
    caixa.setAttribute("aria-hidden", "true");
    caixa.innerHTML = `<div class="cena-quadro"></div><div class="cena-rotulo"><i></i><span></span></div>`;
    palco.appendChild(caixa);
    const quadro = caixa.querySelector(".cena-quadro");
    const rotuloTxt = caixa.querySelector(".cena-rotulo span");
    let atual = null;

    function acender(nome) {
      const cena = cenaDoNome(nome).cena;
      let alvo = FERRAS.find(f => f.re.test(String(nome || "")));
      if (!alvo) alvo = FERRAS.find(f => f.cena === cena);   // sem match exato, acende pela categoria
      for (const id in orbes) orbes[id].classList.toggle("on", !!alvo && id === alvo.id);
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
        acender(nome);
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
