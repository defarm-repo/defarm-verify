#!/usr/bin/env python3
"""
defarm-sig-ts — o CANÁRIO do carimbo de tempo de ASSINATURA (N1 D3), verificado SEM a DeFarm.

Contexto (D3): cada assinatura anexada verificada do dia vira uma folha; as folhas do dia formam uma
`signature_root` (Merkle-SHA256, a MESMA árvore do C2, outro `root_domain`); a root é carimbada 1x/dia
por uma TSA (RFC 3161). O /verify expõe, por assinatura, o `trusted_timestamp` — estado + prova de
inclusão + o ACT. Este canário roda de fora e prova, para cada assinatura de um /verify:

  1. leaf_hash recomputado SÓ dos campos publicados == proof.leaf_hash        (byte-exatidão)
  2. subir a inclusion_proof (position+siblings) == proof.root_hash_sha256    (esta folha ESTÁ na root)
  3. o manifesto no IPFS (proof.act.timestamp_token_cid) recompõe a MESMA root das folhas e o carimbo
     RFC 3161 confere (openssl ts -verify -digest, cadeia até a CA)           (a root foi carimbada)
  4. a root do /verify == a root do manifesto, e esta folha está entre as folhas do manifesto

Se os quatro passam, esta assinatura existia até o genTime do carimbo, atestado por uma TSA — sem a
palavra da DeFarm. Reusa os primitivos do `defarm_act.py` (árvore, JCS, verificação RFC 3161) — a
mesma construção, um só código (não duas cópias que divergem, classe #504).

ALARME (a invariante do #509, o pedido do Hetzner de "virar alarme em vez de silêncio"): uma
assinatura `materialized_pending_stamp` há MAIS que `--max-pending-days` (default 3 = margem+cadência
diária+folga) NÃO é pendência normal — é um dia que não carimbou (worker parado, ou margem subida em
prod). O canário sai != 0 nesse caso, para um cron/monitor gritar em vez de o silêncio parecer normal.

Requisito: `openssl` no PATH. Deps Python: só stdlib (+ certifi se disponível, p/ o TLS do macOS).

Uso:
  # de um /verify já baixado (o modo reproduzível, sem tocar a API mais de uma vez):
  python3 defarm_sig_ts.py --verify-json verify.json
  # buscando o /verify de uma URL (ex.: cron):
  python3 defarm_sig_ts.py --verify-url https://.../api/verify/DFID-... --json
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime, timezone

import defarm_act as act

# Gateways IPFS públicos (mesma lista do defarm_verify.py). NÃO importamos o defarm_verify: ele exige
# `blake3` (p/ recomputar content_hash) que este canário não usa — o carimbo é sobre a signature_root,
# não sobre o conteúdo do evento. Fetch via `act._http_get` (que já monta o SSL com certifi).
DEFAULT_IPFS_GATEWAYS = [
    "https://gateway.pinata.cloud/ipfs",
    "https://ipfs.io/ipfs",
    "https://cloudflare-ipfs.com/ipfs",
]

# O universo D3 — SEPARADO do content_root do C2. A árvore/JCS/RFC3161 são iguais (reusados).
SIG_BATCH_SCHEMA = "defarm.signature_timestamp_batch.v1"
SIG_LEAF_SCHEMA = "defarm.signature_timestamp_leaf.v1"
SIG_ROOT_DOMAIN = "signature_root_v1"

GREEN, RED, YELLOW, DIM, BOLD, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m",
)


def _fetch(url: str) -> bytes:
    return act._http_get(url)


def leaf_from_verify(a: dict) -> dict:
    """Reconstrói a folha `defarm.signature_timestamp_leaf.v1` SÓ dos campos que o /verify publica em
    `attached_signatures[i]`. `signed_value_sha256` = SHA-256 dos bytes decodificados de
    `signed_value_b64` (o /verify publica o b64; a folha carrega o hash). Todo o resto é 1:1. A ordem
    aqui é irrelevante — o JCS reordena as chaves; o que importa é o CONJUNTO exato."""
    signed = base64.b64decode(a["signed_value_b64"])
    tgt = a.get("target", {})
    return {
        "schema": SIG_LEAF_SCHEMA,
        "root_domain": SIG_ROOT_DOMAIN,
        "source_event_id": a["source_event_id"],
        "target_event_id": tgt["event_id"],
        "target_content_hash": tgt["content_hash"],
        "signer_workspace_id": a["signer_workspace_id"],
        "signer_key_id": a["signer_key_id"],
        "signature_format": a["format"],
        "statement_hash_alg": a["statement_hash_alg"],
        "statement_hash": a["statement_hash"],
        "signed_value_sha256": hashlib.sha256(signed).hexdigest(),
        "attached_created_at": a["attached_created_at"],
    }


def verify_inclusion(leaf_hash_hex: str, position: int, siblings: list[str], root_hex: str) -> bool:
    """Sobe a folha até a root pela prova de inclusão. A paridade (irmão à esquerda/direita) vem do
    bit de `position` em cada nível; combine(l,r)=SHA-256(l++r hex COMO TEXTO) — idêntico à árvore do
    servidor. Recompõe a root e confere == `root_hex`."""
    h = leaf_hash_hex.lower()
    idx = position
    for sib in siblings:
        if idx % 2 == 0:
            h = hashlib.sha256((h + sib).encode()).hexdigest()
        else:
            h = hashlib.sha256((sib + h).encode()).hexdigest()
        idx //= 2
    return h == root_hex.lower()


def fetch_manifest(cid: str, gateways: list[str]) -> dict:
    """Baixa o manifesto `defarm.signature_timestamp_batch.v1` por CID de um gateway IPFS público."""
    last = None
    for gw in gateways:
        try:
            return json.loads(_fetch(f"{gw.rstrip('/')}/{cid}"))
        except Exception as e:  # tenta o próximo gateway
            last = e
    raise RuntimeError(f"não consegui baixar o manifesto {cid} de nenhum gateway: {last}")


def pending_age_days(attached_created_at: str) -> float | None:
    """Idade (em dias) de uma assinatura pendente, do `attached_created_at` (RFC3339) até agora (UTC).
    `None` se a data não parsear (não vira alarme por um parse ruim; reporta desconhecido)."""
    s = attached_created_at.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).total_seconds() / 86400.0


def check_signature(a: dict, gateways: list[str], max_pending_days: float) -> dict:
    """Verifica UMA assinatura anexada do /verify. Retorna {status, ok, alarm, reasons, ...}.
    status: verified | pending | stale_pending(ALARME) | not_timestamped | error."""
    ts = a.get("trusted_timestamp") or {}
    state = ts.get("state", "not_timestamped")
    key = a.get("signer_key_id", "?")

    if state == "not_timestamped":
        return {"status": "not_timestamped", "ok": True, "alarm": False, "signer_key_id": key}

    if state == "materialized_pending_stamp":
        age = pending_age_days(a.get("attached_created_at", ""))
        stale = age is not None and age > max_pending_days
        return {
            "status": "stale_pending" if stale else "pending",
            "ok": True,               # pendência em si não é FALHA de prova...
            "alarm": stale,           # ...mas pendente demais é ALARME (#509).
            "age_days": round(age, 2) if age is not None else None,
            "signer_key_id": key,
        }

    if state != "timestamped" or not ts.get("proof"):
        return {"status": "error", "ok": False, "alarm": False,
                "reasons": [f"estado inesperado {state!r} sem prova"], "signer_key_id": key}

    p = ts["proof"]
    reasons: list[str] = []

    # 1) byte-exatidão: o leaf_hash recomputado dos campos publicados == o publicado.
    try:
        recomputed_leaf = act.leaf_hash(leaf_from_verify(a))
    except Exception as e:
        return {"status": "error", "ok": False, "alarm": False,
                "reasons": [f"não montei a folha do /verify: {e}"], "signer_key_id": key}
    declared_leaf = (p.get("leaf_hash") or "").lower()
    leaf_match = recomputed_leaf == declared_leaf
    if not leaf_match:
        reasons.append(f"leaf_hash recomputado ({recomputed_leaf}) != publicado ({declared_leaf})")

    # 2) inclusão: a prova sobe até a root declarada.
    ip = p.get("inclusion_proof", {})
    root_hex = (p.get("root_hash_sha256") or "").lower()
    incl = verify_inclusion(declared_leaf, ip.get("position", -1), ip.get("siblings", []), root_hex)
    if not incl:
        reasons.append("a prova de inclusão NÃO recompõe a root declarada")

    # 3) manifesto no IPFS: recompõe a root inteira das folhas + carimbo RFC 3161 confere.
    manifest_res: dict = {"ok": False}
    leaf_in_manifest = False
    try:
        cid = p["act"]["timestamp_token_cid"]
        manifest = fetch_manifest(cid, gateways)
        ca_url = manifest.get("tsa_ca_url")
        ca_pem = _fetch(ca_url) if ca_url else b""
        manifest_res = act.verify_batch_manifest(
            manifest, ca_pem, None,
            expected_schema=SIG_BATCH_SCHEMA, expected_leaf_schema=SIG_LEAF_SCHEMA,
        )
        if not manifest_res.get("ok"):
            reasons.append("manifesto não confere: " + "; ".join(manifest_res.get("reasons", []) or ["root/carimbo"]))
        # 4) a root do /verify == a root do manifesto, e esta folha está entre as folhas do manifesto.
        if (manifest.get("root_hash_sha256") or "").lower() != root_hex:
            reasons.append("root do /verify != root do manifesto")
        leaf_in_manifest = declared_leaf in {act.leaf_hash(x) for x in manifest.get("leaves", [])}
        if not leaf_in_manifest:
            reasons.append("esta folha NÃO está entre as folhas do manifesto")
    except Exception as e:
        reasons.append(f"falha ao baixar/verificar o manifesto: {e}")

    ok = leaf_match and incl and manifest_res.get("ok") and leaf_in_manifest and not reasons
    return {
        "status": "verified" if ok else "error",
        "ok": bool(ok),
        "alarm": False,
        "reasons": reasons,
        "signer_key_id": key,
        "root": root_hex,
        "gen_time": manifest_res.get("gen_time"),
        "provider": manifest_res.get("provider"),
        "legal_profile": manifest_res.get("legal_profile"),
    }


def collect_signatures(verify_doc: dict) -> list[dict]:
    out: list[dict] = []
    for e in verify_doc.get("events", []) or []:
        for a in e.get("attached_signatures", []) or []:
            out.append(a)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Canário do carimbo de tempo de assinatura (N1 D3), verificado sem a DeFarm.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--verify-json", help="arquivo com o JSON do /verify (ou '-' para stdin)")
    src.add_argument("--verify-url", help="URL do /verify a baixar")
    ap.add_argument("--ipfs-gateway", action="append", dest="gateways",
                    help="gateway IPFS público (repetível; default: pinata, ipfs.io, cloudflare)")
    ap.add_argument("--max-pending-days", type=float, default=3.0,
                    help="ALARME se uma assinatura ficar pendente mais que isto (default 3 = margem+cadência+folga)")
    ap.add_argument("--json", action="store_true", help="saída JSON (exit 0/1 igual)")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    gateways = args.gateways or DEFAULT_IPFS_GATEWAYS
    g, r, y, dim, b, x = (GREEN, RED, YELLOW, DIM, BOLD, RESET) if (sys.stdout.isatty() and not args.no_color) else ("",) * 6

    if args.verify_json:
        raw = sys.stdin.read() if args.verify_json == "-" else open(args.verify_json, encoding="utf-8").read()
        doc = json.loads(raw)
    else:
        doc = json.loads(_fetch(args.verify_url))

    sigs = collect_signatures(doc)
    results = [check_signature(a, gateways, args.max_pending_days) for a in sigs]

    n_ok = sum(1 for x_ in results if x_["status"] == "verified")
    n_alarm = sum(1 for x_ in results if x_.get("alarm"))
    n_fail = sum(1 for x_ in results if not x_["ok"])
    ok_overall = n_fail == 0 and n_alarm == 0

    if args.json:
        print(json.dumps({
            "dfid": doc.get("dfid"),
            "signatures": len(results),
            "verified": n_ok,
            "alarms": n_alarm,
            "failures": n_fail,
            "ok": ok_overall,
            "results": results,
        }, ensure_ascii=False, indent=2))
        return 0 if ok_overall else 1

    print(f"{b}defarm-sig-ts{x} — {doc.get('dfid','?')}  ({len(results)} assinatura(s) anexada(s))")
    if not results:
        print(f"  {dim}nenhuma assinatura anexada neste item{x}")
    for res in results:
        key = (res.get("signer_key_id") or "?")[:20]
        st = res["status"]
        if st == "verified":
            print(f"  {g}✓{x} {key}  carimbada {dim}({res.get('gen_time')}, {res.get('provider')}/{res.get('legal_profile')}){x}")
        elif st == "pending":
            print(f"  {y}…{x} {key}  pendente {dim}(há {res.get('age_days')}d — normal até ~{args.max_pending_days:g}d){x}")
        elif st == "stale_pending":
            print(f"  {r}!{x} {key}  {r}ALARME{x}: pendente há {res.get('age_days')}d (> {args.max_pending_days:g}d) — o dia não carimbou (#509)")
        elif st == "not_timestamped":
            print(f"  {dim}·{x} {key}  sem carimbo ainda")
        else:
            print(f"  {r}✗{x} {key}  FALHA: {'; '.join(res.get('reasons', []))}")
    tail = f"{g}OK{x}" if ok_overall else f"{r}FALHA{x}"
    print(f"  {b}→ {tail}{x}  verified={n_ok} alarmes={n_alarm} falhas={n_fail}")
    return 0 if ok_overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
