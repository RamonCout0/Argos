from argos import didatica
from argos.schema import Finding, Severidade, Fix, FixTipo


def _f(cat, sev=Severidade.ALTO):
    return Finding(id="X", titulo="t", severidade=sev, categoria=cat, origem="s",
                   local="a.py:1", fix=Fix(FixTipo.IA, "f", "p"))


def test_faixa_cvss_por_severidade():
    assert didatica.para_dict(_f("CWE-89", Severidade.CRITICO))["cvss_rotulo"] == "Crítico"
    assert didatica.para_dict(_f("CWE-89", Severidade.BAIXO))["cvss_faixa"] == "0.1–3.9"


def test_sqli_owasp_e_top25_com_links():
    d = didatica.para_dict(_f("CWE-89"))
    assert "OWASP Top 10" in d["quao_comum"] and "CWE Top 25" in d["quao_comum"]
    urls = [l["url"] for l in d["links"]]
    assert "https://cwe.mitre.org/data/definitions/89.html" in urls
    assert any("A03_2021" in u for u in urls)


def test_prompt_injection_aponta_pro_owasp_llm():
    d = didatica.para_dict(_f("CWE-1427"))
    assert any("llm01" in l["url"].lower() for l in d["links"])


def test_cwe_desconhecida_tem_link_mitre_e_comum_generico():
    d = didatica.para_dict(_f("CWE-99999"))
    assert d["links"] and d["links"][0]["url"].endswith("/99999.html")
    assert len(d["links"]) == 1              # só o link MITRE, sem OWASP
    assert "fora das listas" in d["quao_comum"]


def test_entra_no_to_dict_do_finding():
    assert "didatica" in _f("CWE-79").to_dict()
