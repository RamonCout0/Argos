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
        "Credencial escrita no codigo vai junto pro git e pra toda copia do projeto. "
        "Quem le o repositorio ganha o mesmo acesso que voce.",
        "Mover pra variavel de ambiente (.env fora do git) e ROTACIONAR a chave, "
        "porque ela ja foi exposta.",
    ),
    "CWE-259": (
        "Senha fixa no codigo e igual pra todo mundo e aparece no historico do git.",
        "Ler a senha de variavel de ambiente ou cofre de segredos e trocar a senha atual.",
    ),
    "CWE-78": (
        "Montar comando de sistema com texto que vem de fora deixa um atacante "
        "encadear comandos proprios (ex.: '; apaga tudo').",
        "Passar os argumentos como lista, sem shell=True, e validar a entrada "
        "contra uma lista do que e permitido.",
    ),
    "CWE-95": (
        "eval/exec rodam qualquer codigo recebido: quem controla a entrada controla o servidor.",
        "Trocar por ast.literal_eval (so dados) ou por um parser especifico do formato esperado.",
    ),
    "CWE-89": (
        "Concatenar texto do usuario dentro de SQL permite ler ou apagar dados do banco.",
        "Usar consulta parametrizada ou o ORM (no Django, filter() em vez de raw() com f-string).",
    ),
    "CWE-79": (
        "Dado do usuario renderizado sem escape vira script rodando no navegador de outras pessoas (XSS).",
        "Deixar o template escapar a saida; nao usar |safe ou mark_safe com dado do usuario.",
    ),
    "CWE-327": (
        "Algoritmos como MD5 e SHA1 sao quebrados ha anos; senha guardada assim e recuperavel.",
        "Pra senha, usar bcrypt ou argon2 (no Django, o hasher padrao de senhas ja resolve).",
    ),
    "CWE-916": (
        "Hash de senha rapido demais deixa testar bilhoes de senhas por segundo se o banco vazar.",
        "Usar um hash lento feito pra senha: argon2, bcrypt ou PBKDF2 com muitas iteracoes.",
    ),
    "CWE-307": (
        "Sem limite de tentativas, um bot testa milhares de senhas no teu login.",
        "Limitar tentativas por IP/usuario com bloqueio progressivo (no Django: django-axes "
        "ou django-ratelimit).",
    ),
    "CWE-319": (
        "Dado trafegando em HTTP puro pode ser lido por qualquer um no caminho da rede.",
        "Forcar HTTPS (no Django: SECURE_SSL_REDIRECT=True e HSTS) e nunca mandar dado pessoal por HTTP.",
    ),
    "CWE-532": (
        "Dado pessoal ou token em log fica guardado e espalhado em lugares que ninguem protege.",
        "Remover ou mascarar CPF, e-mail, senha e token antes de logar.",
    ),
    "CWE-668": (
        "Servico ouvindo em todas as interfaces: qualquer aparelho no mesmo wifi "
        "(cafe, faculdade, trabalho) consegue conectar nele.",
        "No dev, escutar so em 127.0.0.1. Em producao, deixar atras de firewall ou proxy "
        "e expor so o que o publico precisa.",
    ),
    "CWE-306": (
        "Servico sem autenticacao aberto pra rede: quem conectar usa direto, sem senha "
        "(Redis, Memcached, Ollama...).",
        "Escutar so em 127.0.0.1 (Ollama: OLLAMA_HOST=127.0.0.1; Redis: bind 127.0.0.1) "
        "ou exigir autenticacao e fechar no firewall.",
    ),
    "CWE-359": (
        "Dado pessoal (CPF, e-mail) trafegando sem criptografia pode ser lido no caminho; "
        "vazamento disso e incidente de LGPD.",
        "HTTPS em todo endpoint que recebe dado pessoal e nunca colocar CPF ou e-mail na URL.",
    ),
    "CWE-489": (
        "Modo debug ligado mostra stacktrace, variaveis e configuracao pra qualquer visitante.",
        "Ler o debug de variavel de ambiente com padrao desligado (DEBUG=False em producao).",
    ),
}

GENERICO = (
    "Padrao de codigo conhecido por abrir brecha de seguranca.",
    "Revisar o trecho seguindo a recomendacao da regra que apontou o problema.",
)


def explicacao_base(categoria: str) -> tuple[str, str]:
    return TEMPLATES.get(categoria.upper().strip(), GENERICO)
