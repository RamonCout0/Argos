# Projeto de EXEMPLO, de proposito inseguro, pra testar o Argos.
# Os "segredos" aqui sao FALSOS e existem so pra o gitleaks ter o que achar.
# NAO use nada disto em codigo real.

DEBUG = True

# Personal Access Token do GitHub (ghp_ + 36 chars) -- formato que o gitleaks casa
GITHUB_TOKEN = "ghp_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ"

# AWS Access Key Id (AKIA + 16) -- sem a palavra EXAMPLE, que o gitleaks ignora
AWS_ACCESS_KEY_ID = "AKIAQJ7XR3ZL5MN2PV8T"

# chave generica de alta entropia
SECRET_KEY = "d41d8cd98f00b204e9800998ecf8427e9f3a1b7c"

DATABASE_URL = "postgres://admin:senha123@localhost:5432/app"

# bloco de chave privada -- gatilho quase garantido do gitleaks
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Q
uKUpRKfFLfRYC9AIKjbJTWit+CqvjtZNuyBkC3xyz0FAKEfakeFAKEfake1234==
-----END RSA PRIVATE KEY-----"""
