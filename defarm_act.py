#!/usr/bin/env python3
"""
defarm-act — a TERCEIRA TESTEMUNHA: carimbo de tempo RFC 3161 (ACT) sobre a `daily_root`.

Contexto (C2 do roadmap de verificabilidade): o `content_root` de cada item já viaja on-chain
no Stellar (C1) e é recomputável por um terceiro (defarm_verify.py). O C2 acrescenta uma
TERCEIRA testemunha independente: 1 vez por dia, a DeFarm monta uma Merkle root SHA-256 das
content_roots confirmadas do dia (`daily_root`) e pede um carimbo RFC 3161 a uma Autoridade de
Carimbo do Tempo (TSA). Com um provedor credenciado ICP-Brasil (ex.: SERPRO ACT) isso vira DATA
com PRESUNÇÃO LEGAL, não só anterioridade pública on-chain. O protocolo é o mesmo RFC 3161 tanto
na TSA gratuita de teste (FreeTSA) quanto na ICP-Brasil — a diferença é a cadeia de certificados.

Este módulo é a REFERÊNCIA + o VERIFICADOR do mecanismo: cria e confere o carimbo, e é o que um
terceiro roda pra validar a 3a testemunha SEM a DeFarm — usando só o padrão RFC 3161 (openssl),
não um validador proprietário. O que o /verify vai expor (trusted_timestamps[]) casa com isto:
recompõe o cr (C1) → a folha → a Merkle proof → a daily_root → e confere que o carimbo é sobre
essa daily_root, com genTime confiável.

Requisito: `openssl` no PATH (ts + dgst). Sem dependências Python fora da stdlib.

Uso:
  # criar um carimbo sobre uma daily_root e conferi-lo (prova o mecanismo ponta a ponta):
  python3 defarm_act.py --root-hex <sha256-hex-64> --tsa https://freetsa.org/tsr \\
      --ca-url https://freetsa.org/files/cacert.pem --tsa-cert-url https://freetsa.org/files/tsa.crt

  # conferir um carimbo já emitido (o que um terceiro faz):
  python3 defarm_act.py --root-hex <hex> --token resp.tsr --ca cacert.pem --tsa-cert tsa.crt
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

# Versões que este verificador SABE reproduzir. Um manifesto com valor diferente é RECUSADO cedo
# (Hetzner #484): melhor recusar um alg desconhecido que calcular a árvore errada em silêncio.
EXPECTED_BATCH_SCHEMA = "defarm.act_timestamp_batch.v1"
EXPECTED_ROOT_ALG = "defarm.merkle-sha256-hextext.v1"
EXPECTED_LEAF_SCHEMA = "defarm.act_timestamp_leaf.v1"

try:
    import certifi

    _SSL = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL = ssl.create_default_context()

GREEN, RED, YELLOW, DIM, BOLD, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m",
)


def _run(args: list[str], stdin: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, input=stdin, capture_output=True)


def _http_get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "defarm-act/0.1"})
    with urllib.request.urlopen(req, timeout=30, context=_SSL) as r:
        return r.read()


def request_timestamp(root: bytes, tsa_url: str) -> bytes:
    """Pede um carimbo RFC 3161 com messageImprint = SHA-256(root) a uma TSA. Retorna o token DER
    (TimeStampResp). O imprint é o SHA-256 da daily_root — NÃO o BLAKE3 cru (RFC 3161 usa alg por
    OID; SHA-256 é universal). O terceiro recompõe SHA-256(daily_root) e confere == imprint."""
    with tempfile.TemporaryDirectory() as td:
        data = Path(td) / "root.bin"
        data.write_bytes(root)
        tsq_path = Path(td) / "req.tsq"
        # -out ARQUIVO (não '-out -'): na LibreSSL o stdout binário do DER sai corrompido e a TSA
        # rejeita com badDataFormat. Escrever em arquivo e reler é o caminho provado no spike.
        q = _run(["openssl", "ts", "-query", "-data", str(data), "-sha256", "-cert", "-out", str(tsq_path)])
        if q.returncode != 0 or not tsq_path.exists():
            raise RuntimeError(f"openssl ts -query falhou: {q.stderr.decode(errors='replace')}")
        tsq = tsq_path.read_bytes()
        req = urllib.request.Request(
            tsa_url,
            data=tsq,
            headers={"Content-Type": "application/timestamp-query", "User-Agent": "defarm-act/0.1"},
        )
        with urllib.request.urlopen(req, timeout=40, context=_SSL) as r:
            return r.read()


def token_info(token_der: bytes) -> dict:
    """Extrai genTime + imprint (hex) do token, via `openssl ts -reply -text`."""
    with tempfile.TemporaryDirectory() as td:
        tf = Path(td) / "resp.tsr"
        tf.write_bytes(token_der)
        out = _run(["openssl", "ts", "-reply", "-in", str(tf), "-text"])
        text = out.stdout.decode(errors="replace")
    info: dict = {"gen_time": None, "imprint_hex": None, "policy_oid": None, "hash_alg": None}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith("Time stamp:"):
            info["gen_time"] = s.split(":", 1)[1].strip()
        elif s.startswith("Policy OID:"):
            info["policy_oid"] = s.split(":", 1)[1].strip()
        elif s.startswith("Hash Algorithm:"):
            info["hash_alg"] = s.split(":", 1)[1].strip()
        elif s.startswith("Message data:"):
            # o imprint sai como hex-dump BIO em N linhas ("0000 - 51 f7 ..-.. 77   Q..E..").
            # SHA-256 = 32 bytes = 2 linhas; leio TODAS as linhas de dump seguidas (bug antigo:
            # lia só a primeira -> imprint truncado). Corto o ASCII (separado por 2+ espaços) e o
            # offset "0000 -", e junto os pares hex (o traço do meio, 68-8f, não separa os pares).
            hexbytes: list[str] = []
            j = i + 1
            while j < len(lines):
                m = re.match(r"\s*[0-9a-fA-F]{4}\s*-\s*(.*)$", lines[j])
                if not m:
                    break
                hexregion = re.split(r"\s{2,}", m.group(1))[0]
                hexbytes += re.findall(r"[0-9a-fA-F]{2}", hexregion)
                j += 1
            info["imprint_hex"] = "".join(hexbytes).lower()
            i = j
            continue
        i += 1
    return info


def verify_timestamp(root: bytes, token_der: bytes, ca_pem: bytes, tsa_cert_pem: bytes | None) -> dict:
    """Verificação RFC 3161 padrão (o que um terceiro faz): confere que o token assina o
    messageImprint == SHA-256(root), com assinatura válida encadeada até a CA. Retorna
    {ok, imprint_match, gen_time, ...}. `imprint_match` é conferido AQUI, independente do openssl."""
    info = token_info(token_der)
    expected_imprint = hashlib.sha256(root).hexdigest()
    # cross-check independente do openssl: o imprint no token deve ser EXATAMENTE SHA-256(root).
    imprint_match = info.get("imprint_hex") == expected_imprint
    with tempfile.TemporaryDirectory() as td:
        data = Path(td) / "root.bin"
        data.write_bytes(root)
        tf = Path(td) / "resp.tsr"
        tf.write_bytes(token_der)
        ca = Path(td) / "ca.pem"
        ca.write_bytes(ca_pem)
        args = ["openssl", "ts", "-verify", "-data", str(data), "-in", str(tf), "-CAfile", str(ca)]
        if tsa_cert_pem:
            unt = Path(td) / "tsa.crt"
            unt.write_bytes(tsa_cert_pem)
            args += ["-untrusted", str(unt)]
        v = _run(args)
    verified = v.returncode == 0 and b"Verification: OK" in (v.stdout + v.stderr)
    return {
        "ok": verified and imprint_match,
        "chain_verified": verified,
        "imprint_match": imprint_match,
        "expected_imprint": expected_imprint,
        "token_imprint": info.get("imprint_hex"),
        "gen_time": info.get("gen_time"),
        "policy_oid": info.get("policy_oid"),
        "hash_alg": info.get("hash_alg"),
        "verify_output": (v.stdout + v.stderr).decode(errors="replace").strip(),
    }


def verify_timestamp_digest(root_hex: str, token_der: bytes, ca_pem: bytes, tsa_cert_pem: bytes | None) -> dict:
    """Verificação RFC 3161 no modo -DIGEST (o design do C2): a `daily_root` JÁ é o messageImprint,
    então usa `-digest <root>`, NÃO `-data` (que re-hashearia a root → FAILED; o servidor manda o
    imprint direto). Confere: imprint == root, assinatura, cadeia até a CA da TSA."""
    info = token_info(token_der)
    imprint_match = (info.get("imprint_hex") or "").lower() == root_hex.lower()
    with tempfile.TemporaryDirectory() as td:
        tf = Path(td) / "resp.tsr"
        tf.write_bytes(token_der)
        ca = Path(td) / "ca.pem"
        ca.write_bytes(ca_pem)
        args = ["openssl", "ts", "-verify", "-digest", root_hex, "-in", str(tf), "-CAfile", str(ca)]
        if tsa_cert_pem:
            unt = Path(td) / "tsa.crt"
            unt.write_bytes(tsa_cert_pem)
            args += ["-untrusted", str(unt)]
        v = _run(args)
    verified = v.returncode == 0 and b"Verification: OK" in (v.stdout + v.stderr)
    return {
        "ok": verified and imprint_match,
        "chain_verified": verified,
        "imprint_match": imprint_match,
        "token_imprint": info.get("imprint_hex"),
        "gen_time": info.get("gen_time"),
        "policy_oid": info.get("policy_oid"),
        "verify_output": (v.stdout + v.stderr).decode(errors="replace").strip(),
    }


def leaf_hash(leaf: dict) -> str:
    """SHA-256(JCS(folha)). A folha é só-string, então JCS = json canônico (chaves ordenadas,
    compacto, UTF-8) — bate byte-a-byte com o serde_jcs do servidor (provado na paridade do C2b)."""
    jcs = json.dumps(leaf, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(jcs.encode()).hexdigest()


def daily_root_from_leaves(leaves: list[dict]) -> str | None:
    """Merkle-SHA256 sobre os leaf_hashes ORDENADOS: combine(l,r)=SHA-256(l++r hex COMO TEXTO), nó
    ímpar duplica o último. Espelha `merkle_sha256_daily_root` do servidor (ROOT_ALG
    defarm.merkle-sha256-hextext.v1). `None` = sem folha."""
    level = sorted(leaf_hash(x) for x in leaves)
    if not level:
        return None
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(hashlib.sha256((left + right).encode()).hexdigest())
        level = nxt
    return level[0]


def verify_batch_manifest(manifest: dict, ca_pem: bytes, tsa_cert_pem: bytes | None) -> dict:
    """A prova órfã COMPLETA do C2, a partir do manifesto IPFS (defarm.act_timestamp_batch.v1):
      1. recusa cedo se schema/root_alg/leaf_schema forem desconhecidos (não sei reproduzir);
      2. recompõe a daily_root das FOLHAS e confere == root declarada;
      3. confere o carimbo RFC 3161 (modo -digest) sobre a root: imprint == root, assinatura, cadeia.
    Se os três passam, a root está carimbada por uma TSA cuja cadeia confere — SEM a DeFarm."""
    reasons: list[str] = []
    if manifest.get("schema") != EXPECTED_BATCH_SCHEMA:
        reasons.append(f"schema do manifesto desconhecido: {manifest.get('schema')!r}")
    if manifest.get("root_alg") != EXPECTED_ROOT_ALG:
        reasons.append(f"root_alg desconhecido (não sei reproduzir): {manifest.get('root_alg')!r}")
    if manifest.get("leaf_schema") != EXPECTED_LEAF_SCHEMA:
        reasons.append(f"leaf_schema desconhecido: {manifest.get('leaf_schema')!r}")
    if reasons:
        return {"ok": False, "reasons": reasons}

    leaves = manifest.get("leaves", [])
    declared = (manifest.get("root_hash_sha256") or "").lower()
    recomputed = daily_root_from_leaves(leaves)
    root_match = recomputed is not None and recomputed == declared
    if not root_match:
        reasons.append(f"daily_root recomputada das folhas ({recomputed}) != declarada ({declared})")

    token_der = base64.b64decode(manifest.get("timestamp_token_b64", ""))
    ts = verify_timestamp_digest(declared, token_der, ca_pem, tsa_cert_pem) if declared else {"ok": False}
    if not ts.get("ok"):
        reasons.append("carimbo RFC 3161 não confere: " + (ts.get("verify_output") or "imprint/cadeia"))

    return {
        "ok": root_match and ts.get("ok") and not reasons,
        "reasons": reasons,
        "recomputed_root": recomputed,
        "declared_root": declared,
        "root_match": root_match,
        "leaf_count": len(leaves),
        "gen_time": ts.get("gen_time"),
        "provider": manifest.get("provider"),
        "legal_profile": manifest.get("legal_profile"),
        "policy_oid": ts.get("policy_oid"),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Cria/verifica um carimbo de tempo RFC 3161 (ACT) sobre uma root.")
    ap.add_argument("--manifest", help="JSON do manifesto do lote (defarm.act_timestamp_batch.v1) — a prova órfã COMPLETA do C2: recompõe a daily_root das folhas + verifica o carimbo")
    ap.add_argument("--root-hex", help="a daily_root em hex (modo carimbo único, sem manifesto)")
    ap.add_argument("--token", help="token DER já emitido (.tsr) — modo só-verificar")
    ap.add_argument("--tsa", help="URL da TSA p/ emitir (ex.: https://freetsa.org/tsr)")
    ap.add_argument("--ca", help="arquivo PEM da CA da TSA")
    ap.add_argument("--ca-url", help="URL do PEM da CA (baixa)")
    ap.add_argument("--tsa-cert", help="arquivo do cert intermediário da TSA (untrusted)")
    ap.add_argument("--tsa-cert-url", help="URL do cert intermediário da TSA")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    g, r, y, dim, b, x = (GREEN, RED, YELLOW, DIM, BOLD, RESET) if (sys.stdout.isatty() and not args.no_color) else ("",) * 6

    def _resolve_ca():
        ca = Path(args.ca).read_bytes() if args.ca else (_http_get(args.ca_url) if args.ca_url else None)
        cert = Path(args.tsa_cert).read_bytes() if args.tsa_cert else (_http_get(args.tsa_cert_url) if args.tsa_cert_url else None)
        return ca, cert

    # MODO MANIFESTO — a prova órfã COMPLETA do C2 (recompõe a daily_root das folhas + verifica o carimbo).
    if args.manifest:
        manifest = json.loads(Path(args.manifest).read_text())
        ca_pem, tsa_cert = _resolve_ca()
        # AUTO-SUFICIÊNCIA (Hetzner #487/F2): sem --ca, baixa a RAIZ da própria tsa_ca_url do
        # manifesto — o terceiro roda `--manifest lote.json` e pronto, sem saber a CA por fora.
        if not ca_pem and manifest.get("tsa_ca_url"):
            try:
                ca_pem = _http_get(manifest["tsa_ca_url"])
                print(f"{dim}CA baixada do manifesto (tsa_ca_url): {manifest['tsa_ca_url']}{x}")
            except Exception as e:  # noqa: BLE001
                print(f"{y}~ não baixei a CA de {manifest.get('tsa_ca_url')}: {e}{x}")
        if not ca_pem:
            print(f"{r}sem CA: nem --ca/--ca-url nem tsa_ca_url no manifesto{x}")
            return 2
        print(f"{b}defarm-act{x}  —  manifesto {manifest.get('batch_date','?')} · {manifest.get('provider','?')} · {len(manifest.get('leaves',[]))} folhas")
        fp = manifest.get("tsa_cert_fingerprint")
        if fp:
            print(f"{dim}cert TSA esperado (fingerprint): {fp}{x}")
        res = verify_batch_manifest(manifest, ca_pem, tsa_cert)
        mark = f"{g}✓{x}" if res.get("root_match") else f"{r}✗{x}"
        print(f"{mark} recompus a daily_root das folhas e conferi com a declarada")
        print(f"    declarada  : {res.get('declared_root')}")
        print(f"    recomputada: {res.get('recomputed_root')}")
        print(f"    carimbo    : genTime={res.get('gen_time')} · policy={res.get('policy_oid')} · perfil={res.get('legal_profile')}")
        if res["ok"]:
            print(f"{g}{b}VEREDITO:{x} as {res['leaf_count']} content_roots do dia estão carimbadas em "
                  f"{res.get('gen_time')} — recomposto e verificado sem a DeFarm.")
            return 0
        for reason in res.get("reasons", []):
            print(f"{r}  · {reason}{x}")
        print(f"{r}{b}VEREDITO: o manifesto NÃO confere.{x}")
        return 1

    if not args.root_hex:
        print(f"{r}informe --manifest <arquivo> ou --root-hex <hex>{x}")
        return 2
    try:
        root = bytes.fromhex(args.root_hex.strip())
    except ValueError:
        print(f"{r}--root-hex inválido (esperado hex){x}")
        return 2

    print(f"{b}defarm-act{x}  —  carimbo RFC 3161 sobre a root {args.root_hex[:16]}…")

    # 1) obter o token (emitir na TSA ou ler do arquivo)
    if args.token:
        token = Path(args.token).read_bytes()
        print(f"{dim}token lido de {args.token} ({len(token)} bytes){x}")
    elif args.tsa:
        try:
            token = request_timestamp(root, args.tsa)
        except Exception as e:
            print(f"{r}✗ emissão na TSA falhou{x}: {e}")
            return 2
        print(f"{g}✓{x} carimbo emitido pela TSA ({len(token)} bytes) — {args.tsa}")
    else:
        print(f"{r}informe --token <arquivo> ou --tsa <url>{x}")
        return 2

    # 2) cadeia da CA
    ca_pem = None
    if args.ca:
        ca_pem = Path(args.ca).read_bytes()
    elif args.ca_url:
        ca_pem = _http_get(args.ca_url)
    tsa_cert = None
    if args.tsa_cert:
        tsa_cert = Path(args.tsa_cert).read_bytes()
    elif args.tsa_cert_url:
        tsa_cert = _http_get(args.tsa_cert_url)

    if not ca_pem:
        info = token_info(token)
        print(f"{y}~ sem CA (--ca/--ca-url) — só extraindo o token, sem verificar a cadeia{x}")
        print(f"    genTime  : {info.get('gen_time')}")
        print(f"    imprint  : {info.get('imprint_hex')}")
        print(f"    esperado : {hashlib.sha256(root).hexdigest()}")
        return 0

    # 3) verificação (o que o terceiro faz)
    res = verify_timestamp(root, token, ca_pem, tsa_cert)
    mark = f"{g}✓{x}" if res["ok"] else f"{r}✗{x}"
    print(f"{mark} {b}verificação RFC 3161{x} (imprint == SHA-256(root) + assinatura + cadeia)")
    print(f"    genTime          : {res.get('gen_time')}")
    print(f"    imprint esperado : {res['expected_imprint']}")
    print(f"    imprint no token : {res.get('token_imprint')}")
    print(f"    imprint bate     : {res['imprint_match']}")
    print(f"    cadeia/assinatura: {res['chain_verified']}  ({res.get('verify_output')})")
    if res["ok"]:
        print(f"{g}{b}VEREDITO:{x} a root está carimbada em {res.get('gen_time')} por uma TSA cuja "
              f"cadeia confere — a terceira testemunha, validada sem a DeFarm.")
        return 0
    print(f"{r}{b}VEREDITO: o carimbo NÃO confere{x}.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
