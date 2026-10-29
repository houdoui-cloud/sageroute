import pytest

from app.models import IocType
from app.services import ioc as svc
from tests.conftest import ANALYST, auth, new_incident

API = "/api/v1"


@pytest.mark.parametrize("value,expected", [
    ("203.0.113.5", IocType.IPV4),
    ("2001:db8::1", IocType.IPV6),
    ("evil-bank.example", IocType.DOMAIN),
    ("evil-bank[.]example", IocType.DOMAIN),
    ("hxxp://evil-bank[.]example/login", IocType.URL),
    ("attacker@evil-bank.example", IocType.EMAIL),
    ("44d88612fea8a8f36de82e1278abb02f", IocType.MD5),
    ("3395856ce81f2b7382dee72602f798b642f14140", IocType.SHA1),
    ("3f786850e387550fdab836ed7e6dc881de23001b3f786850e387550fdab836ed", IocType.SHA256),
    ("+225 00 00 00 01", IocType.PHONE),
    ("facture.pdf", None),
    ("bonjour", None),
])
def test_detect_type(value, expected):
    assert svc.detect_type(value) == expected


def test_extract_from_bulletin():
    text = ("Le lien hxxps://momo-verif[.]example/x renvoie vers 198.51.100.7. Expéditeur : fraud@momo-verif.example. "
            "Fichier facture.pdf, empreinte 44D88612FEA8A8F36DE82E1278ABB02F.")
    found = svc.extract(text)
    assert (IocType.URL, "https://momo-verif.example/x") in found
    assert (IocType.IPV4, "198.51.100.7") in found
    assert (IocType.EMAIL, "fraud@momo-verif.example") in found
    assert (IocType.MD5, "44d88612fea8a8f36de82e1278abb02f") in found
    assert all(v != "facture.pdf" for _, v in found)
    assert (IocType.DOMAIN, "momo-verif.example") not in found  # covered by URL/email


def test_enrich_documentation_ranges():
    assert svc.enrich("ipv4", "192.0.2.1")["documentation_range"] is True
    assert svc.enrich("ipv4", "10.0.0.1")["private"] is True


def test_create_dedup_and_validation(client):
    headers = auth(client, ANALYST)
    a = client.post(f"{API}/intel/iocs", json={"value": "Dedup-Test.EXAMPLE", "confidence": 40}, headers=headers)
    assert a.status_code == 201 and a.json()["type"] == "domain" and a.json()["value"] == "dedup-test.example"
    b = client.post(f"{API}/intel/iocs", json={"value": "dedup-test[.]example", "confidence": 90}, headers=headers).json()
    assert b["id"] == a.json()["id"] and b["sightings"] == 2 and b["confidence"] == 90
    bad = client.post(f"{API}/intel/iocs", json={"value": "203.0.113.9", "type": "domain"}, headers=headers)
    assert bad.status_code == 422
    assert client.post(f"{API}/intel/iocs", json={"value": "pas un ioc"}, headers=headers).status_code == 422


def test_link_to_incident_and_enrich(client):
    headers = auth(client, ANALYST)
    inc = new_incident(client, headers)
    ioc = client.post(f"{API}/intel/iocs", json={"value": "203.0.113.200", "incident_id": inc["id"]},
                      headers=headers).json()
    assert ioc["incident_refs"] == [inc["reference"]]
    detail = client.get(f"{API}/incidents/{inc['id']}", headers=headers).json()
    assert detail["iocs"][0]["value"] == "203.0.113.200"
    info = client.get(f"{API}/intel/iocs/{ioc['id']}/enrich", headers=headers).json()
    assert info["documentation_range"] is True and info["incidents"] == [inc["reference"]]
    after = client.delete(f"{API}/intel/iocs/{ioc['id']}/link/{inc['id']}", headers=headers).json()
    assert after["incident_refs"] == []


def test_import_and_match(client):
    headers = auth(client, ANALYST)
    res = client.post(f"{API}/intel/iocs/import", headers=headers, json={
        "text": "203.0.113.150\nimport-a.example\nhxxp://import-b[.]example/p\n", "source": "test"}).json()
    assert res == {"extracted": 3, "created": 3, "updated": 0}
    m = client.post(f"{API}/intel/match", headers=headers,
                    json={"text": "Connexion vers 203.0.113.150 et inconnu-zz.example"}).json()
    assert m["extracted"] == 2 and m["matches"] == 1


def test_feed_is_seeded_and_sync_idempotent(client):
    headers = auth(client, ANALYST)
    feed = client.get(f"{API}/intel/feed", headers=headers).json()
    assert len(feed) >= 5
    assert client.post(f"{API}/intel/feed/sync", headers=headers).json()["added"] == 0
    ransomware = client.get(f"{API}/intel/feed", params={"tag": "ransomware"}, headers=headers).json()
    assert ransomware and all("ransomware" in i["tags"] for i in ransomware)


def test_export_excludes_red_by_default(client):
    headers = auth(client, ANALYST)
    client.post(f"{API}/intel/iocs", json={"value": "tres-secret.example", "tlp": "red"}, headers=headers)
    assert "tres-secret.example" not in client.get(f"{API}/intel/iocs/export", headers=headers).text
    full = client.get(f"{API}/intel/iocs/export", params={"include_red": True, "fmt": "json"}, headers=headers)
    assert "tres-secret.example" in full.text
