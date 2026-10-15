"""Verifica sin confiar en nadie: python verificar.py"""
import json, hashlib, glob, os
from cryptography.hazmat.primitives import serialization
pub = serialization.load_pem_public_key(open("llave_publica.pem", "rb").read())
canon = lambda d: json.dumps(d, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
disco = hashlib.sha256(open("disco.txt", "rb").read()).hexdigest()
for f in sorted(glob.glob("mensajes/*.firma.json")):
    s = json.load(open(f, encoding="utf-8"))
    texto = open(f.replace(".firma.json", ".txt"), "rb").read()
    assert hashlib.sha256(texto).hexdigest() == s["huella_texto"], f + ": texto alterado"
    cuerpo = {k: v for k, v in s.items() if k != "firma"}
    pub.verify(bytes.fromhex(s["firma"]), hashlib.sha256(canon(cuerpo)).digest())
    print("ok", os.path.basename(f), "| reglas:", s["huella_reglas"][:16], "| vigentes" if s["huella_reglas_publicas"] == disco else "| OTRA VERSION DEL DISCO")
if os.path.exists("cadena_publica.jsonl"):
    prev = "0" * 64
    for i, l in enumerate(open("cadena_publica.jsonl", encoding="utf-8")):
        e = json.loads(l)
        assert e["n"] == i and e["prev"] == prev, f"eslabon {i} roto"
        if not e.get("reservado"):
            assert hashlib.sha256(canon({k: v for k, v in e.items() if k not in ("hash", "firma")})).hexdigest() == e["hash"], f"entrada {i} alterada"
        pub.verify(bytes.fromhex(e["firma"]), bytes.fromhex(e["hash"]))
        prev = e["hash"]
    print(f"cadena integra: {i + 1} entradas")
