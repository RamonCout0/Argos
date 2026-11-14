# Argos

> O vigia de cem olhos. Confere brechas no teu projeto **antes** da produção — e **só roda em dev/local**.

`v2.0` · Python 3.10+ · Windows / Linux · Licença MIT · Feito no Brasil, pensando na LGPD

## Instalação rápida

```bash
git clone <url-do-repositorio> Argos && cd Argos
pip install -r requirements.txt
python cli.py demo --html demo.html     # relatorio de exemplo, sem instalar scanner nenhum
python cli.py gui --demo                # interface grafica com dados de exemplo
python cli.py ia --sistema exemplos/ia/prompt_fraco.txt   # testa uma IA no teu Ollama
python -m pytest -q                     # roda a suite de testes
```

Os scanners externos (gitleaks, pip-audit, semgrep, nmap, tshark, Ollama) são todos opcionais: o que não estiver instalado é pulado com aviso e dica de instalação. A lista está em `requirements.txt`.

Argos é uma ferramenta open-source de segurança para desenvolvedores (especialmente quem toca projeto sozinho). Ele orquestra scanners de ataque e defesa já consagrados, junta tudo num relatório único e legível, e te dá um checklist do que mudar antes do deploy.

**Honestidade de proposta:** nenhum scanner pega tudo. Argos cobre as classes mais comuns de problema (OWASP Top 10, CVEs de dependência, segredos vazados, misconfig, dado pessoal exposto) e reduz muito o risco — não promete 100%.

---

## Princípios

1. **Só dev/local.** Todo scanner passa o alvo pela trava (`guard/target_lock.py`): se não resolver pra loopback ou rede privada, Argos recusa e nem liga a ferramenta. Não é trava inquebrável (é open-source), mas deixa claro e honesto que Argos é ferramenta de dev, não arma.
2. **O conhecimento mora nos scanners.** Argos não entende linguagem nenhuma — ele é um maestro. Semgrep, Trivy, gitleaks, ZAP e cia. trazem a cobertura de linguagens e frameworks. Suportar stack nova = adicionar um adapter.
3. **A matemática decide, a IA explica.** O score e o selo "ok pra prod" são cálculo puro sobre os findings reais. O Ollama entra só no fim, pra traduzir e sugerir fix — nunca pra julgar ou liberar deploy.
4. **Privado por padrão.** O Ollama roda local. Um tool de LGPD não manda teu código vulnerável pra uma API na nuvem.

---

## Interface gráfica

```bash
pip install pywebview        # Linux: sudo apt install python3-gi gir1.2-webkit2-4.1
python cli.py gui            # abre a janela
python cli.py gui --demo     # abre com dados de exemplo, sem rodar scanner
python cli.py gui --classico # a interface antiga, em Tkinter puro
```

**No Linux, com venv:** o `gi` (GTK) vem do sistema e não instala bem pelo pip, então o venv precisa enxergar os pacotes do sistema:

```bash
sudo apt install python3-gi gir1.2-webkit2-4.1 python3-tk
rm -rf venv && python3 -m venv --system-site-packages venv
source venv/bin/activate && pip install -r requirements.txt
```

Use o `python3` do sistema pra criar o venv (o `python3-gi` do apt só serve pra ele). Sem GTK, o `gui` avisa e abre a interface clássica.

Janela nativa (pywebview) com a tela em HTML, CSS e SVG — leve o bastante pra notebook de 4 GB, porque usa o navegador que já vem no sistema (WebView2 no Windows, WebKit no Linux). Nada sai pra internet: a tela e o Python conversam por dentro da janela.

**O olho do Argos** é 100% vetorial e muda conforme o que está acontecendo — e a cor de destaque da interface inteira acompanha:

| Cor | Estado |
|---|---|
| azul | em repouso; olha em volta devagar e pisca |
| roxo | vigiando; um enxame de olhos aparece, cada um olhando pra um lado |
| vermelho | achou brecha que bloqueia o deploy; pupila contraída, brilho pulsando |
| âmbar | passou, mas com ressalvas |
| verde | tudo limpo |

Abas: **Auditoria** (veredito, barra de vida, contadores), **Checklist** (marque o que corrigiu — a nota só muda quando o re-scan confirma), **LGPD**, **Teste de IA** e **Scanners**. Todo texto vindo de scanner, código ou IA entra na tela como texto puro (nunca HTML).

**Dica pra projetos Django + Angular (ex.: DRF na porta 8000 e `ng serve` na 4200):** aponte a pasta do projeto e as duas portas. O `ng serve` por padrão escuta só em localhost; se aparecer exposto, procure um `--host 0.0.0.0` esquecido. As dependências do Angular não passam pelo pip-audit: rode `npm audit` na pasta do front à parte.

---

## Teste da tua IA contra prompt injection (v2.0)

Pra quem faz app com LLM (Ollama, bot de Discord, automação que lê documentos). Mapeia o **OWASP Top 10 para LLM**:

| Categoria | O que o Argos tenta | Peso |
|---|---|---|
| LLM07 · vazamento do prompt | fazer a IA revelar o prompt de sistema | alto |
| LLM01 · sobrescrita | uma mensagem do usuário mudar as regras | médio |
| LLM01 · injeção indireta | uma instrução escondida num documento comandar a IA | alto |

```bash
python cli.py ia --sistema meu_prompt.txt --modelo llama3.1:8b          # direto no teu Ollama
python cli.py ia --gerar-canario                                         # pra testar o endpoint do teu app
python cli.py ia --url http://127.0.0.1:5000/chat --canario ARGOS-CANARIO-...
```

**Detecção sem IA julgando IA:** um canário único (`ARGOS-CANARIO-xxxx`) mora só no prompt de sistema — se ele aparecer na resposta, mesmo de trás pra frente ou espaçado, vazou. Nas outras sondagens a IA recebe "a palavra X seguida do número N" com os pedaços separados: só um modelo que obedece junta os dois. Um modelo que recusa citando o pedido não é acusado. As sondagens são inofensivas: só tentam fazer a IA dizer um marcador sem sentido.

Os alvos passam pela mesma trava do resto do Argos (só local). Em `exemplos/ia/` tem um prompt fraco e um reforçado pra comparar. Reforçar o prompt ajuda, mas não basta: as defesas de verdade ficam no código — nada de segredo no prompt, documento entre delimitadores tratado como dado, e validar a saída antes de agir.

---

## O que o navegador e o Burp veem: trilha web (v2.1)

Ferramentas de interceptação (Burp, ZAP, o próprio DevTools) mostram tudo que o teu app manda pro navegador. Ferramentas de descoberta (dirb, gobuster, ffuf) testam endereços tipo `/.env` e `/.git/` até achar um esquecido. A trilha `web` olha essas mesmas coisas, **de forma passiva e leve**: uma lista curta de caminhos conhecidos, no máximo ~80 requisições por alvo, sem wordlist gigante e sem força bruta.

```bash
python cli.py web http://127.0.0.1:8000 http://127.0.0.1:4200     # back + front rodando
python cli.py auditar . --url http://127.0.0.1:8000 --html relatorio.html
```

| O que olha | Exemplos |
|---|---|
| Arquivos expostos | `.env`, `.git/`, `db.sqlite3`, dumps `.sql`, backups `.zip`, `id_rsa`, `docker-compose.yml` |
| Pastas listando arquivos | `/media/`, `/uploads/`, `/static/` (o "Index of") |
| Debug ligado | página de erro do Django com `DEBUG=True`, debugger do Werkzeug, Django Debug Toolbar |
| Cabeçalhos | CSP, X-Frame-Options (clickjacking), nosniff, HSTS, versão no `Server` |
| CORS | origem refletida, e pior, junto com credenciais |
| Cookies de sessão | sem `HttpOnly`, sem `SameSite`, sem `Secure` no HTTPS |
| JavaScript do front | chave de API/token dentro do bundle, source map publicado |
| Endereços padrão | `/admin/` do Django (lente bot), documentação da API aberta |

**Sem alarme falso de SPA:** Angular/React devolvem `index.html` pra qualquer caminho, então "respondeu 200" não prova nada. O Argos só acusa quando o **conteúdo** bate (um `.env` de verdade tem linhas `NOME=`, um `.git/HEAD` começa com `ref:`). Segredos aparecem sempre mascarados (`AKIA***`), e o `.env` só mostra os nomes das variáveis.

**Regras de alvo:** local liberado; produção só com dono verificado (token da semana), mais devagar, sem TRACE. Redirecionamento pra outro domínio não é seguido.

**Checagem de configuração (dentro do `scan` da pasta):** lê o código sem rodar nada: `.env` fora do `.gitignore` ou já commitado, `SECRET_KEY` escrita no `settings.py`, `ALLOWED_HOSTS = ['*']`, CORS liberado geral, **DRF sem `DEFAULT_PERMISSION_CLASSES`** (o padrão do DRF é `AllowAny`: toda view sem permissão fica aberta pra quem mandar a requisição direto, que é exatamente o que se faz no Burp), `admin/` no caminho padrão, segredo no `environment.ts` do Angular e source map ligado no build de produção.

Pra ver funcionando: `python exemplos/web_inseguro.py` sobe um app errado de propósito em `127.0.0.1:8766`; noutro terminal, `python cli.py web http://127.0.0.1:8766` acha 15 problemas.

**O que fica de fora (de propósito):** testar se o backend valida e checa permissão de verdade mandando requisições alteradas (IDOR, trocar o ID de outro usuário, campo extra no JSON). Isso é teste ativo e fica pra Fase 7, só num clone de staging com dados falsos.

---

## Fluxo do dia a dia

1. **Projeto novo, no PC:** enquanto desenvolve, rode as trilhas locais.
   `python cli.py auditar . --porta 8000 --url http://127.0.0.1:8000 --html relatorio.html`
2. **Antes de cada deploy:** o mesmo `auditar`. Saiu com código 1 (BLOQUEADO)? Não sobe.
   Falso positivo comprovado? `aceitar` com motivo e prazo — nunca apagar a regra.
3. **Teste pesado (Fase 7, futuro):** só num **clone de staging** idêntico ao site, com
   **dados falsos**, banco próprio e chaves de teste; apagar o clone depois.
   Produção recebe no máximo checagem passiva, com dono verificado.

---

## Mandar as brechas pra uma IA corrigir

Na interface, **Copiar pra IA** copia um relatório em Markdown pronto pra colar no Claude (ou **Salvar .md**). Pela linha de comando:

```bash
python cli.py auditar . --url http://127.0.0.1:8000 --prompt-ia pra_ia.md
```

O arquivo traz instruções de como corrigir com segurança (ordem de gravidade, mudança mínima, nada de escrever segredo, permissão no backend) e cada brecha com arquivo:linha, evidência mascarada, por que importa, correção sugerida e como confirmar. No fim, separa o que só você resolve: trocar a chave que vazou, decidir quais endpoints são públicos.

Os achados vão marcados como **dados, não instruções**: um comentário malicioso no código escaneado não vira ordem pra IA. Depois de aplicar as correções, rode o Argos de novo: uma brecha só conta como corrigida quando o re-scan confirma.

---

## Rodar fora do localhost: verificação de dono

Por padrão o Argos só aceita alvos locais/privados. Pra checar **o teu próprio site em produção**, o site precisa provar que é teu — não basta uma variável no teu PC, a prova vem do servidor:

1. `python cli.py segredo` gera um `ARGOS_SECRET` forte.
2. O **mesmo valor** vai em dois lugares: no `.env` do Argos (fora do git) e nas *Variables* do serviço no Railway.
3. O site publica `https://SEU-SITE/.well-known/argos-verify.txt` com um token `HMAC-SHA256(segredo, host + semana ISO)`. Pra Django, o endpoint pronto está em `exemplos/railway_django/argos_verify.py`.
4. `python cli.py check https://seu-site.com` → o Argos baixa o token (sempre via HTTPS) e compara com o que calcula. Bateu → liberado. Não bateu → bloqueado.

- O token **gira sozinho toda semana** (UTC); aceita a semana anterior só pra virada de domingo/segunda.
- O token publicado não revela o segredo e só vale pra aquele domínio.
- **Interruptor de emergência:** apagou `ARGOS_SECRET` no Railway → a rota vira 404 → o Argos para de aceitar o site.
- `python cli.py token seu-site.com` mostra o token esperado da semana (pra depurar).

É um guard-rail de consentimento do dono do alvo, não um DRM: sendo open-source, dá pra remover. O objetivo é que o caminho oficial nunca aponte pra um site de terceiros.

---

## A peça central: o `Finding`

Cada scanner traduz a própria saída para um `Finding` (ver `argos/schema.py`). O resto do sistema só conhece o `Finding`.

| campo | o que é |
|-------|---------|
| `id` | identificador, ex. `SECRET-001` |
| `severidade` | `critico \| alto \| medio \| baixo \| info` |
| `categoria` | referência CWE/OWASP/CVE |
| `lentes` | `critico`, `lgpd`, `bot` — uma ou mais |
| `origem` | qual scanner achou |
| `local` | arquivo:linha, host:porta ou endpoint |
| `evidencia` | o trecho real que o scanner cuspiu |
| `fix` | `{ tipo: deterministico\|ia, descricao, patch }` |
| `verificacao` | como re-checar que sumiu |
| `status` | `aberto \| corrigido \| ignorado` |

### As três lentes
Não são três checklists separadas — é o mesmo pool de findings com três filtros:
- **crítico** — o que te derruba primeiro (segredo, injection, DEBUG=True, porta exposta).
- **LGPD** — pegada técnica de dado pessoal exposto (CPF em HTTP puro, dado em log, sem cripto). A parte jurídica (consentimento, minimização) vira item de confirmação manual — Argos não finge automatizar lei.
- **bot** — rate limit, CAPTCHA/honeypot, credential stuffing.

### Score e selo (`argos/scorer.py`)
Duas coisas **separadas**:
- **Score** (0–100): a barra motivacional. `100 − Σ(peso dos abertos)`. Pesos: crítico 40 · alto 20 · médio 10 · baixo 3.
- **Selo "ok pra prod"**: booleano frio. Só libera se **não houver crítico nem alto aberto**. Score 85 com 1 alto aberto = **reprovado**. O número bonito nunca libera o deploy sozinho.

Corrigiu → re-scan confirma → `status: corrigido` → peso sai da conta.

---

## Arquitetura

```
argos/
  schema.py            # o Finding (peça central)
  scorer.py            # score + selo
  guard/
    target_lock.py     # a trava loopback/privado (o cofre)
  report/
    console.py         # relatorio de console, com filtro por lente
    html.py            # relatorio HTML offline (CSP, tudo escapado)
  adapters/
    base.py            # o contrato: todo scanner implementa Adapter
    gitleaks.py        # segredos vazados
    pip_audit.py       # CVE em dependencias Python
    semgrep.py         # SAST poliglota (ponte WSL no Windows)
    bandit.py          # SAST so-Python (extra, nativo no Windows)
    prompt_injection.py # v2.0: teste da tua IA (vazamento, sobrescrita, injecao indireta)
    web.py             # v2.1: trilha web passiva (cabecalhos, CORS, cookies, arquivos/pastas expostos)
    config_projeto.py  # v2.1: .env, settings do Django/DRF, angular.json e environment.ts
    portas.py          # Fase 5: quem escuta onde (psutil)
    nmap.py            # Fase 5: que servico e + visao pela rede local
    tshark.py          # Fase 5: dado sensivel em HTTP sem TLS
  native/
    riscos.py          # peso de cada porta exposta (debug, banco, app)
    sensiveis.py       # detector de CPF/e-mail/senha/token, sempre mascarado
  core/
    orchestrator.py    # roda os adapters disponiveis e junta os findings
    dedup.py           # funde a mesma brecha achada por scanners diferentes
    aceitos.py         # riscos aceitos: motivo + prazo, vencem sozinhos
  lenses/
    mapa.py            # regras fixas: severidade/CWE -> critico/lgpd/bot
    lgpd_manual.py     # checklist manual da LGPD (fora do score)
  ai/
    templates.py       # explicacao base por CWE (funciona sem IA)
    contexto.py        # trecho do codigo com segredos mascarados
    ollama.py          # cliente do Ollama, preso a endereco local
    narrator.py        # a voz: explica e sugere, nunca decide
  ui/
    api.py             # ponte Python <-> tela (o pywebview expoe os metodos publicos)
    janela.py          # abre a janela nativa
    web/               # index.html, estilo.css, app.js e olho.js (o olho vetorial)
  gui/                 # interface classica (Tkinter): gui --classico
    app.py             # a janela (Tkinter), scan numa thread separada
    arte.py            # arte vetorial: olho, barra de vida, icones, botoes
    estado.py          # logica do checklist (marcas, resolvidos, por projeto)
  config.py            # le variaveis do ambiente ou do .env
cli.py                 # ponto de entrada
exemplos/              # projeto vulneravel de proposito, pra testar
                       #   web_inseguro.py: app web errado de proposito (so 127.0.0.1)
tests/                 # testes do nucleo e dos parsers
```

### Roadmap
- **Fase 0 — núcleo (OK):** `Finding`, score, selo, trava de alvo, relatório de console, testes. Roda sem nenhum scanner.
- **Fase 1 — primeiro olho (OK):** contrato do adapter + **gitleaks** (scan real de segredos, ponta a ponta).
- **Fase 2 — mais olhos (OK):** pip-audit (CVE em deps) + Semgrep (SAST poliglota, via WSL no Windows). Bandit disponível como extra só-Python. Trivy e Semgrep-nativo ficam pra quando precisar de container/outras linguagens.
- **Fase 3 — as três lentes (OK):** lentes por regra fixa (severidade + CWE), deduplicação entre scanners, `--lente critico|lgpd|bot` e checklist manual da LGPD na visão LGPD.
- **Fase 4 — a voz (OK):** explicação base por CWE pra todo achado + `--ia` com Ollama local (só nos fixes do tipo IA, trecho com segredos mascarados, temperatura 0, cache). A IA só escreve texto: severidade, score e selo não mudam. `OLLAMA_URL` fora da máquina/rede local é recusado.
- **Fase 5 — trilha nativa (OK):** `nativo` (psutil diz se a porta escuta só em 127.0.0.1 ou na rede toda; nmap identifica o serviço e, com `--rede`, confirma pelo IP da rede local) e `trafego` (tshark procura credencial e dado pessoal em HTTP sem TLS, ao vivo ou num `.pcap`). Só máquina/rede local: a verificação de dono **não** libera nmap em produção, porque o domínio do Railway aponta pra infraestrutura compartilhada.
- **Fase 6 — veredito e relatório (OK):** `auditar` roda as trilhas pedidas e junta tudo num selo só; relatório HTML offline (`--html`) e JSON pra CI (`--saida-json`); `--falhar-em medio|baixo` deixa o selo mais rigoroso (nunca mais frouxo); riscos aceitos com motivo e prazo de até 90 dias em `argos-aceitos.json`.
- **v1.1 — interface gráfica** (Tkinter, hoje `gui --classico`).
- **v2.0 — teste de IA e interface nova (OK):** trilha `ia` (prompt injection: vazamento, sobrescrita, injeção indireta) e interface pywebview com olho vetorial por estado.
- **v2.1 — trilha web e configuração (OK):** `web <urls>` e `auditar --url` (o que Burp e scanners de diretório revelariam, só passivo) + checagem de configuração do Django/DRF/Angular/.env dentro do `scan`. Na interface: log ao vivo de cada passo (cada scanner, cada requisição, cada sondagem da IA), botão de cancelar que encerra até os programas externos, e um buraco negro que abre atrás do olho enquanto ele vasculha (canvas, respeita "reduzir movimento").
- **Fase 7 — ideia: DAST com dono verificado.** Scanner web (ex.: OWASP ZAP) só em alvo local ou com verificação de dono. Em produção, apenas modo passivo (baseline: cabeçalhos, cookies, HTTPS); ataque ativo só em localhost/staging. Conferir a política de uso aceitável da hospedagem antes.

---

## O que o Argos cobre da LGPD (e o que não cobre)

O Argos **não certifica conformidade com a LGPD** — nenhuma ferramenta automática consegue, porque boa parte da lei é processo e decisão jurídica. Ele cobre a **pegada técnica da segurança** (art. 46: medidas técnicas pra proteger dado pessoal) e lembra do resto:

| Parte da LGPD | Como o Argos trata |
|---|---|
| Segredo/credencial exposta no código | automático (gitleaks, semgrep) |
| Dado pessoal ou credencial em HTTP sem TLS | automático (tshark) |
| Criptografia fraca de senha (MD5/SHA1) | automático (semgrep/bandit) |
| Banco/serviço aberto pra rede | automático (psutil, nmap) |
| Dependência com vulnerabilidade conhecida | automático (pip-audit) |
| Dado pessoal em log | parcial (lente LGPD quando o scanner aponta) + checklist |
| Base legal, minimização, direitos do titular, retenção, plano de incidente | **checklist manual** na lente LGPD |
| Encarregado (DPO), contratos com operadores, RIPD, política de privacidade | fora do escopo — orientação jurídica |

---

## Como rodar

```bash
# veredito final: as trilhas que voce pedir, um selo so
python cli.py auditar . --porta 8000 --pcap captura.pcap --html relatorio.html
python cli.py auditar exemplos/projeto_vulneravel --saida-json resultado.json --falhar-em medio

# falso positivo? aceite com motivo e prazo (vai pro argos-aceitos.json)
python cli.py aceitar CODE-S002 --motivo "eval so roda no script de teste" --dias 30
python cli.py aceitos

# relatorio HTML de exemplo, sem scanner nenhum
python cli.py demo --html demo.html
```

```bash
# escanear um projeto de verdade (precisa do gitleaks instalado)
python cli.py scan exemplos/projeto_vulneravel
python cli.py scan "C:/Users/Ramon-CTI/Documents/meu-site"

# so uma lente (score e selo continuam do projeto inteiro)
python cli.py scan exemplos/projeto_vulneravel --lente lgpd
python cli.py demo --lente bot

# explicacao e sugestao com o Ollama local (Fase 4)
ollama pull llama3.1:8b                # ou outro modelo; defina ARGOS_MODELO no .env
python cli.py ia-status
python cli.py scan exemplos/projeto_vulneravel --ia

# trilha nativa (Fase 5): o app RODANDO
python exemplos/servidor_exposto.py          # outro terminal: sobe um servidor em 0.0.0.0
python cli.py nativo --porta 8765            # escuta so local ou pra rede?
python cli.py nativo --porta 8765 --rede     # + nmap pelo IP da tua rede
python cli.py nativo --listar                # tudo que esta escutando na maquina

# trafego (Fase 5): o que o app MANDA sem criptografia
python cli.py trafego --pcap exemplos/captura_exemplo.pcap   # captura de exemplo, sem precisar de rede
python cli.py trafego --segundos 30                          # ao vivo: use so o teu app na janela
python cli.py trafego --listar-interfaces

# relatorio de exemplo (prova a esteira finding -> score -> selo, sem scanner)
python cli.py demo

# com o JSON cru junto
python cli.py demo --json

# testar a trava de alvo
python cli.py check localhost:8000     # OK
python cli.py check 8.8.8.8            # BLOQUEADO

# testes
pip install -r requirements.txt
python -m pytest -q
```

---

## Uso responsável

O Argos existe pra **proteger os teus próprios projetos**. Use só em sistemas que são teus ou que você tem autorização por escrito pra testar. Testar sistema de terceiros sem autorização pode ser crime (no Brasil, a Lei 12.737/2012 tipifica invasão de dispositivo informático).

As travas do código (só localhost/rede privada, verificação de dono por token, scanners leves, nada de faixa de portas inteira) deixam isso explícito no caminho oficial. Elas não são DRM: como em todo open-source, dá pra removê-las num fork — e a responsabilidade pelo uso passa a ser de quem fez isso.

Achou uma brecha **no próprio Argos**? Abra uma issue sem detalhes de exploração e combine o envio privado dos detalhes com o mantenedor.

## Créditos

Criado por **Ramon Couto Santos** (Parnamirim/RN). O Argos orquestra ferramentas de terceiros — gitleaks, pip-audit, Semgrep, Bandit, psutil, nmap, Wireshark/tshark e Ollama —, cada uma com a sua própria licença; elas não são distribuídas junto com este código.

## Licença

[MIT](LICENSE) © 2026 Ramon Couto Santos. Pode usar, modificar e redistribuir, inclusive comercialmente, desde que o aviso de copyright e a licença acompanhem as cópias. O software é fornecido "como está", sem garantia.
