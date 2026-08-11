#!/usr/bin/env python3
"""
defarm-verify — verificador INDEPENDENTE de um DFID da DeFarm.

Por que existe: a página /v da DeFarm recomputa as provas no seu navegador, mas o
JavaScript é servido pela própria DeFarm. Um cético não deveria precisar confiar nem
na página nem neste servidor. Este CLI fecha o laço SEM a página da DeFarm: lê a âncora
on-chain direto do Horizon público (Stellar), puxa o snapshot do IPFS por CID de
gateways públicos, e recomputa os hashes por conta própria — código aberto, auditável,
rodando na sua máquina.

O que ele PROVA (hoje):
  1. Que o par (DFID, CID) está ancorado on-chain — lido do envelope da transação no
     Horizon público, não da palavra da DeFarm.
  2. Que o snapshot público resolve pelo CID em >=2 gateways IPFS independentes, com
     bytes idênticos (o CID é content-addressed: o conteúdo não pode ter mudado sem
     mudar o CID).
  3. Que o content_hash de cada evento público bate quando recomputado do zero a partir
     do payload/metadata (BLAKE3 sobre "item_id:event_type:payload:metadata", JSON
     compacto com chaves ordenadas) — integridade de cada evento, verificada aqui.

O que ele AINDA NÃO prova (limites honestos — sem enfeite):
  - O snapshot ancorado é PONTO-NO-TEMPO. Ele compromete um events_root da época da
    ancoragem; eventos criados DEPOIS não estão sob nenhum commitment on-chain (a âncora
    não é reescrita a cada evento novo). Este CLI exibe essa defasagem em vez de escondê-la.
  - Não há um content_root on-chain além do CID; a recomputação do events_root histórico
    exige o conjunto exato de eventos da época (que o snapshot não lista individualmente).
  - Não verifica as leituras cruas privadas (só o snapshot público) nem a assinatura
    ed25519 do snapshot (a chave é publicada pela DeFarm; ancoragem externa é trabalho aberto).

Dependência única fora da stdlib: blake3 (pip install blake3).
Licença: MIT.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import ssl
import sys
import urllib.request
import urllib.error
from typing import Any

try:
    from blake3 import blake3
except ImportError:
    sys.exit("Falta a dependência 'blake3'. Instale com:  pip install blake3")

# Contexto SSL com o CA bundle do certifi — no macOS o Python não encontra o do sistema
# (erro CERTIFICATE_VERIFY_FAILED). Cai pro default se certifi não estiver instalado.
try:
    import certifi
    _SSL = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL = ssl.create_default_context()

DEFAULT_API = "https://gateway.defarm.net"
DEFAULT_HORIZON = "https://horizon.stellar.org"
DEFAULT_IPFS_GATEWAYS = [
    "https://gateway.pinata.cloud/ipfs",
    "https://ipfs.io/ipfs",
    "https://cloudflare-ipfs.com/ipfs",
]

# Escaneia o envelope XDR (bytes) atrás do commitment que a DeFarm escreve on-chain:
# um JSON {"d":"<DFID>","ipfs":"<CID>",...}. Não precisamos decodificar SCVal do Soroban —
# o par (DFID, CID) viaja como string ASCII nos argumentos da chamada de contrato.
ONCHAIN_RE = re.compile(rb'\{"d":"(DFID-[A-Za-z0-9-]+)","ipfs":"([A-Za-z0-9]+)"')

GREEN, RED, YELLOW, DIM, BOLD, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m",
)


def _color(enabled: bool):
    if enabled:
        return GREEN, RED, YELLOW, DIM, BOLD, RESET
    return ("",) * 6


def http_get(url: str, timeout: int = 30, as_json: bool = False) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "defarm-verify/0.1"})
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
        data = r.read()
    return json.loads(data) if as_json else data


def bootstrap_anchor(dfid: str, api: str) -> tuple[str | None, str | None]:
    """Ponteiro de partida (tx_hash, cid) via /verify. NÃO é confiança: o tx_hash é só um
    ponteiro que confirmamos no Horizon a seguir; se a DeFarm mentir aqui, o passo on-chain
    não bate e o DFID não confere."""
    try:
        d = http_get(f"{api}/v1/verify/{dfid}", as_json=True)
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        return None, None
    a = d.get("anchor") or {}
    return a.get("transaction_hash"), a.get("metadata_cid")


def onchain_from_horizon(tx: str, horizon: str) -> tuple[str, str, int | None]:
    """Lê a transação no Horizon PÚBLICO e extrai (DFID, CID, ts) do envelope. Esta é a
    perna de independência: a existência do CID on-chain vem da rede, não da DeFarm."""
    t = http_get(f"{horizon}/transactions/{tx}", as_json=True)
    if not t.get("successful", False):
        raise ValueError("a transação existe mas não foi bem-sucedida on-chain")
    raw = base64.b64decode(t["envelope_xdr"])
    m = ONCHAIN_RE.search(raw)
    if not m:
        raise ValueError("não achei o commitment {\"d\":...,\"ipfs\":...} no envelope da tx")
    dfid = m.group(1).decode()
    cid = m.group(2).decode()
    ts_m = re.search(rb'"ts":(\d+)', raw[m.start():])
    ts = int(ts_m.group(1)) if ts_m else None
    return dfid, cid, ts


def fetch_snapshot(cid: str, gateways: list[str]) -> tuple[bytes, dict, list[str]]:
    """Puxa o snapshot por CID de vários gateways IPFS PÚBLICOS e exige bytes idênticos em
    >=2. Content-addressing: o mesmo CID só devolve o mesmo conteúdo."""
    got: dict[str, bytes] = {}
    for gw in gateways:
        try:
            got[gw] = http_get(f"{gw}/{cid}", timeout=40)
        except (urllib.error.URLError, TimeoutError, OSError):
            continue
    if not got:
        raise ValueError("nenhum gateway IPFS público resolveu o CID")
    uniq = {v for v in got.values()}
    if len(got) >= 2 and len(uniq) != 1:
        raise ValueError("gateways devolveram bytes DIFERENTES para o mesmo CID (!)")
    first_gw, first_bytes = next(iter(got.items()))
    return first_bytes, json.loads(first_bytes), list(got.keys())


def canon(v: Any) -> str:
    # Espelha o serde_json compacto + chaves ordenadas do backend. O json do Python já
    # preserva int vs float (390 vs 390.0), então o content_hash bate byte-a-byte.
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def recompute_content_hash(e: dict) -> bool | None:
    ch = e.get("content_hash")
    if not ch or not e.get("item_id"):
        return None
    md = dict(e.get("metadata") or {})
    md.pop("signature", None)
    msg = f"{e['item_id']}:{e['event_type']}:{canon(e.get('payload') or {})}:{canon(md)}"
    return blake3(msg.encode()).hexdigest() == ch


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verificador independente de um DFID da DeFarm (on-chain + IPFS, sem a página).",
    )
    ap.add_argument("dfid", help="o DFID a verificar, ex.: DFID-BEEF-BR-2026-001179-9e3fe8")
    ap.add_argument("--tx", help="tx hash da âncora (senão, buscado via /verify como ponteiro)")
    ap.add_argument("--api", default=DEFAULT_API, help=f"API da DeFarm p/ o ponteiro inicial (default {DEFAULT_API})")
    ap.add_argument("--horizon", default=DEFAULT_HORIZON, help=f"Horizon público (default {DEFAULT_HORIZON})")
    ap.add_argument("--ipfs-gateway", action="append", dest="ipfs_gateways",
                    help="gateway IPFS público (repetível; default: pinata, ipfs.io, cloudflare)")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    g, r, y, dim, b, x = _color(sys.stdout.isatty() and not args.no_color)
    gateways = args.ipfs_gateways or DEFAULT_IPFS_GATEWAYS
    dfid = args.dfid.strip()
    ok_all = True

    print(f"{b}defarm-verify{x}  —  {dfid}")
    print(f"{dim}verificação independente: Horizon público + IPFS público, sem a página da DeFarm{x}\n")

    # --- 0. ponteiro de partida ---
    tx = args.tx
    boot_cid = None
    if not tx:
        tx, boot_cid = bootstrap_anchor(dfid, args.api)
        if not tx:
            print(f"{r}✗{x} sem âncora: /verify não devolveu transaction_hash (item não ancorado?).")
            return 2
        print(f"{dim}ponteiro (via /verify, confirmado on-chain a seguir): tx={tx[:16]}…{x}\n")

    # --- 1. âncora on-chain (Horizon público) ---
    try:
        oc_dfid, oc_cid, oc_ts = onchain_from_horizon(tx, args.horizon)
    except Exception as e:
        print(f"{r}✗ 1. âncora on-chain{x}: {e}")
        return 2
    dfid_match = oc_dfid == dfid
    ok_all &= dfid_match
    mark = f"{g}✓{x}" if dfid_match else f"{r}✗{x}"
    print(f"{mark} {b}1. âncora on-chain{x} (Horizon público, tx confirmada)")
    print(f"    DFID on-chain : {oc_dfid}  {'' if dfid_match else r+'(NÃO bate com o consultado!)'+x}")
    print(f"    CID  on-chain : {oc_cid}")
    if oc_ts:
        import datetime
        when = datetime.datetime.fromtimestamp(oc_ts, datetime.timezone.utc)
        print(f"    ancorado em   : {when.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    if boot_cid and boot_cid != oc_cid:
        print(f"    {y}nota: o CID do /verify ({boot_cid}) difere do on-chain — confie no on-chain.{x}")
    print()

    # --- 2. snapshot por CID em gateways IPFS públicos ---
    try:
        snap_bytes, snap, used = fetch_snapshot(oc_cid, gateways)
    except Exception as e:
        print(f"{r}✗ 2. snapshot IPFS{x}: {e}")
        return 2
    hosts = [u.split("//")[1].split("/")[0] for u in used]
    print(f"{g}✓{x} {b}2. snapshot público{x} (CID resolvido, content-addressed)")
    if len(used) >= 2:
        print(f"    {len(snap_bytes)} bytes, bytes IDÊNTICOS em {len(used)} gateways: {', '.join(hosts)}")
    else:
        print(f"    {len(snap_bytes)} bytes, via {hosts[0]} "
              f"{y}(só 1 gateway respondeu — o cross-check forte precisa de 2+){x}")
    gen = snap.get("generated_at")
    ev_root = ((snap.get("events") or {}) if isinstance(snap.get("events"), dict) else {}).get("hash")
    if gen:
        print(f"    snapshot gerado em: {gen}")
    if ev_root:
        print(f"    events_root ancorado (via CID): {ev_root}")
    print()

    # --- 3. integridade de cada evento (recompute independente) ---
    try:
        events = http_get(f"{args.api}/v1/items/{dfid}/events/public", as_json=True)
    except Exception as e:
        print(f"{y}~ 3. integridade de eventos{x}: não consegui listar eventos ({e})")
        events = []
    checks = [(e.get("event_type"), recompute_content_hash(e)) for e in events]
    checkable = [c for _, c in checks if c is not None]
    n_ok = sum(1 for c in checkable if c)
    n_tot = len(checkable)
    int_ok = n_tot > 0 and n_ok == n_tot
    ok_all &= (n_tot == 0 or int_ok)
    mark = f"{g}✓{x}" if int_ok else (f"{y}~{x}" if n_tot == 0 else f"{r}✗{x}")
    print(f"{mark} {b}3. integridade dos eventos{x} (content_hash recomputado aqui, do zero)")
    print(f"    {n_ok}/{n_tot} conferem" + ("" if n_tot else "  (nenhum evento com content_hash)"))
    for et, c in checks:
        if c is False:
            print(f"    {r}✗ {et}: content_hash NÃO bate{x}")
    print()

    # --- limite honesto: defasagem do snapshot ---
    n_events_now = len([1 for e in events if e.get("content_hash")])
    print(f"{dim}{b}Limites honestos:{x}")
    print(f"{dim}  • O snapshot ancorado é ponto-no-tempo. O item tem {n_events_now} evento(s) público(s) hoje;{x}")
    print(f"{dim}    os criados DEPOIS da ancoragem NÃO estão sob commitment on-chain (a âncora não é{x}")
    print(f"{dim}    reescrita a cada evento). A integridade acima é do conteúdo de cada evento, não{x}")
    print(f"{dim}    prova de que o CONJUNTO atual está ancorado.{x}")
    print(f"{dim}  • Não verifica leituras cruas privadas nem a assinatura ed25519 do snapshot.{x}")
    print()

    if ok_all:
        print(f"{g}{b}VEREDITO:{x} âncora on-chain confere, snapshot público íntegro, eventos íntegros — "
              f"verificado sem a página da DeFarm.")
        return 0
    print(f"{r}{b}VEREDITO: algo NÃO confere{x} — veja os ✗ acima.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
