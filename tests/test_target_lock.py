import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argos.guard.target_lock import validar_alvo, alvo_e_local, AlvoNaoLocal  # noqa: E402


def test_localhost_ok():
    assert alvo_e_local("localhost") is True


def test_loopback_ip_ok():
    assert validar_alvo("127.0.0.1") == ["127.0.0.1"]


def test_url_localhost_ok():
    assert alvo_e_local("http://localhost:8000") is True


def test_host_porta_ok():
    assert alvo_e_local("127.0.0.1:8000") is True


def test_rede_privada_ok():
    assert alvo_e_local("192.168.0.10") is True


def test_ip_publico_bloqueado():
    assert alvo_e_local("8.8.8.8") is False


def test_dominio_publico_bloqueado():
    # resolve pra IP publico -> AlvoNaoLocal. Offline, o resolve falha -> tambem AlvoNaoLocal.
    with pytest.raises(AlvoNaoLocal):
        validar_alvo("example.com")
