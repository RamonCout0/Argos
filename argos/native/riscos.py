"""
Argos — o risco de uma porta exposta (regra única, usada por psutil e nmap).

Uma porta "exposta" é uma que escuta em 0.0.0.0/:: (todas as interfaces) ou
num IP da rede: qualquer aparelho no mesmo wifi (café, faculdade, trabalho)
consegue conectar. O peso depende do que está atrás dela.
"""
from __future__ import annotations

import ipaddress

from ..schema import Severidade

# depuracao remota exposta = execucao de codigo pra quem estiver na rede
PORTAS_DEBUG = {
    9229: "Node inspector",
    5678: "debugpy (Python)",
    5005: "Java debug (JDWP)",
    4444: "debugger/shell remoto",
}

# servicos que nunca deveriam ficar abertos pra rede no dev
PORTAS_SENSIVEIS = {
    5432: "PostgreSQL",
    3306: "MySQL/MariaDB",
    1433: "SQL Server",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    11211: "Memcached",
    5984: "CouchDB",
    11434: "Ollama",  # sem autenticacao: qualquer um na rede usa teus modelos
}

SEM_AUTENTICACAO = {6379, 11211, 11434, 9200}

SERVICOS_SENSIVEIS = {
    "postgresql", "mysql", "ms-sql-s", "redis", "mongodb", "mongod",
    "elasticsearch", "memcache", "memcached", "couchdb",
}


def risco_da_porta(porta: int, servico: str = "") -> tuple[Severidade, str, str]:
    """(severidade, categoria CWE, rotulo) de uma porta exposta pra rede."""
    if porta in PORTAS_DEBUG:
        return Severidade.CRITICO, "CWE-489", PORTAS_DEBUG[porta]
    if porta in PORTAS_SENSIVEIS or servico.lower() in SERVICOS_SENSIVEIS:
        rotulo = PORTAS_SENSIVEIS.get(porta, servico or "servico sensivel")
        cwe = "CWE-306" if porta in SEM_AUTENTICACAO else "CWE-668"
        return Severidade.ALTO, cwe, rotulo
    return Severidade.MEDIO, "CWE-668", servico or "app"


def ip_e_local(ip: str) -> bool:
    """Loopback, RFC1918 ou link-local. (Docs/TEST-NET contam como externos.)"""
    try:
        end = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if end.is_loopback or end.is_link_local:
        return True
    redes = [ipaddress.ip_network(r) for r in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]
    return any(end in r for r in redes if r.version == end.version)
