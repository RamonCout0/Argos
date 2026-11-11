# Codigo inseguro de PROPOSITO, pra o bandit/semgrep terem o que achar.
# NAO use nada disto em codigo real.
import hashlib
import subprocess


def roda(cmd):
    # shell=True com input externo -> command injection
    return subprocess.call(cmd, shell=True)


def hash_senha(s):
    # md5 e fraco pra senha
    return hashlib.md5(s.encode()).hexdigest()


def executa(expr):
    # eval em input -> execucao remota de codigo
    return eval(expr)
