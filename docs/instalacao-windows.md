# Instalar o Argos no Windows (executável)

Dois passos: gerar o `Argos.exe` uma vez e rodar o instalador de dependências.

## 1. Gerar o Argos.exe

Precisa de Python instalado só pra esta etapa (depois o exe roda sozinho):

```powershell
pip install pyinstaller pywebview
pyinstaller argos.spec
```

Sai `dist\Argos.exe` — um arquivo só, janela sem console, com o ícone do olho
na barra de tarefas e no alt-tab. É esse que você distribui/usa.

## 2. Instalar as dependências

As trilhas usam ferramentas externas (gitleaks, OSV-Scanner, Trivy, nmap, gh,
Ollama, pip-audit e — para o semgrep — o WSL). O script confere o que falta e
instala, **perguntando antes de cada uma**:

```powershell
# botão direito > "Executar com o PowerShell", ou:
powershell -ExecutionPolicy Bypass -File instalar.ps1
```

Notas:
- Precisa do **winget** (vem no Windows 10/11; se faltar, instale "Instalador de
  Aplicativo" pela Microsoft Store).
- O **WSL** pede administrador e **reinício** na primeira vez. Depois de
  reiniciar, rode o `instalar.ps1` de novo para instalar o semgrep dentro do WSL.
- O Argos **pula sozinho** qualquer ferramenta que não esteja instalada e diz
  qual falta — nenhuma delas é obrigatória para abrir o programa.

## Rodar

Clique no `Argos.exe`. Aponte a pasta do projeto, escolha as trilhas e clique em
Auditar. Para o modo ataque (testes reais), ligue a chave "Modo ataque" — ele só
roda em repositório do GitHub do qual você é colaborador, e só em localhost.
