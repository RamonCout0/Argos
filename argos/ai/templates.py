"""
Argos — explicações base por categoria (o "RAG leve").

Cada CWE comum tem um texto-base escrito à mão: o que é o risco e o caminho
de correção. Isso serve pra duas coisas:
  1. Sem Ollama, o relatório já explica cada brecha (determinístico, grátis).
  2. Com Ollama, o modelo parte DESTE texto e só adapta ao trecho do teu
     código — um 8B se sai muito melhor ajustando do que inventando do zero.
"""
from __future__ import annotations

# CWE -> (o risco, o caminho da correcao)
TEMPLATES: dict[str, tuple[str, str]] = {
    "CWE-798": (
        "Credencial escrita no código vai junto pro git e pra toda cópia do projeto. "
        "Quem lê o repositório ganha o mesmo acesso que você.",
        "Mover pra variável de ambiente (.env fora do git) e TROCAR a chave, "
        "porque ela já foi exposta.",
    ),
    "CWE-259": (
        "Senha fixa no código é igual pra todo mundo e aparece no histórico do git.",
        "Ler a senha de variável de ambiente ou cofre de segredos e trocar a senha atual.",
    ),
    "CWE-78": (
        "Montar comando de sistema com texto que vem de fora deixa um atacante "
        "encadear comandos próprios (ex.: '; apaga tudo').",
        "Passar os argumentos como lista, sem shell=True, e validar a entrada "
        "contra uma lista do que é permitido.",
    ),
    "CWE-95": (
        "eval/exec rodam qualquer código recebido: quem controla a entrada controla o servidor.",
        "Trocar por ast.literal_eval (só dados) ou por um parser específico do formato esperado.",
    ),
    "CWE-89": (
        "Concatenar texto do usuário dentro de SQL permite ler ou apagar dados do banco.",
        "Usar consulta parametrizada ou o ORM (no Django, filter() em vez de raw() com f-string).",
    ),
    "CWE-79": (
        "Dado do usuário renderizado sem escape vira script rodando no navegador de outras pessoas (XSS).",
        "Deixar o template escapar a saída; não usar |safe ou mark_safe com dado do usuário.",
    ),
    "CWE-327": (
        "Algoritmos como MD5 e SHA1 estão quebrados há anos; senha guardada assim é recuperável.",
        "Pra senha, usar bcrypt ou argon2 (no Django, o hasher padrão de senhas já resolve).",
    ),
    "CWE-916": (
        "Hash de senha rápido demais deixa testar bilhões de senhas por segundo se o banco vazar.",
        "Usar um hash lento feito pra senha: argon2, bcrypt ou PBKDF2 com muitas iterações.",
    ),
    "CWE-307": (
        "Sem limite de tentativas, um bot testa milhares de senhas no teu login.",
        "Limitar tentativas por IP/usuário com bloqueio progressivo (no Django: django-axes "
        "ou django-ratelimit).",
    ),
    "CWE-319": (
        "Dado trafegando em HTTP puro pode ser lido por qualquer um no caminho da rede.",
        "Forçar HTTPS (no Django: SECURE_SSL_REDIRECT=True e HSTS) e nunca mandar dado pessoal por HTTP.",
    ),
    "CWE-532": (
        "Dado pessoal ou token em log fica guardado e espalhado em lugares que ninguém protege.",
        "Remover ou mascarar CPF, e-mail, senha e token antes de logar.",
    ),
    "CWE-668": (
        "Serviço ouvindo em todas as interfaces: qualquer aparelho no mesmo wifi "
        "(café, faculdade, trabalho) consegue conectar nele.",
        "No dev, escutar só em 127.0.0.1. Em produção, deixar atrás de firewall ou proxy "
        "e expor só o que o público precisa.",
    ),
    "CWE-306": (
        "Serviço sem autenticação aberto pra rede: quem conectar usa direto, sem senha "
        "(Redis, Memcached, Ollama...).",
        "Escutar só em 127.0.0.1 (Ollama: OLLAMA_HOST=127.0.0.1; Redis: bind 127.0.0.1) "
        "ou exigir autenticação e fechar no firewall.",
    ),
    "CWE-359": (
        "Dado pessoal (CPF, e-mail) trafegando sem criptografia pode ser lido no caminho; "
        "vazamento disso é incidente de LGPD.",
        "HTTPS em todo endpoint que recebe dado pessoal e nunca colocar CPF ou e-mail na URL.",
    ),
    "CWE-489": (
        "Modo debug ligado mostra stacktrace, variáveis e configuração pra qualquer visitante.",
        "Ler o debug de variável de ambiente com padrão desligado (DEBUG=False em produção).",
    ),
}

GENERICO = (
    "Padrão de código conhecido por abrir brecha de segurança.",
    "Revisar o trecho seguindo a recomendação da regra que apontou o problema.",
)


def explicacao_base(categoria: str) -> tuple[str, str]:
    return TEMPLATES.get(categoria.upper().strip(), GENERICO)
