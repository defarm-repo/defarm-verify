# defarm-verify

Um verificador **independente** de um DFID da DeFarm. Roda na sua máquina, com código
aberto e auditável, e fecha o laço de verificação **sem confiar na página nem no servidor
da DeFarm**.

A página pública `defarm.net/v/<DFID>` já recomputa as provas no seu navegador — mas o
JavaScript que faz isso é servido pela própria DeFarm. Um cético não deveria precisar
confiar nisso. Este CLI faz a mesma conta lendo a âncora **direto do Horizon público
(Stellar)** e o snapshot **de gateways IPFS públicos**, e recomputa os hashes por conta
própria.

## O que ele prova (hoje)

1. **A âncora on-chain.** Lê a transação no Horizon público e extrai o par `(DFID, CID)`
   do envelope. Prova que aquele CID está ancorado on-chain para aquele DFID — da rede,
   não da palavra da DeFarm.
2. **O snapshot público.** Resolve o CID em ≥2 gateways IPFS independentes e exige bytes
   idênticos. Como o CID é *content-addressed*, o conteúdo não pode ter mudado sem mudar
   o CID.
3. **A integridade de cada evento.** Recomputa o `content_hash` de cada evento público do
   zero — `BLAKE3("item_id:event_type:payload:metadata")`, com `payload`/`metadata` em
   JSON compacto e chaves ordenadas — e compara com o declarado.
4. **O content_root ON-CHAIN (integridade do conjunto).** Em âncoras novas, o arg `cid` da
   chamada de contrato é um envelope `{v,d,ipfs,cr,ts,vc}` — o `cr` = `anchor_content_root_v1`
   viaja on-chain. O CLI o extrai do XDR e o **recompõe do snapshot** com **JCS RFC 8785 de
   verdade** (`BLAKE3(JCS({schema,dfid,cid,snapshot_hash,events_root,commitments_root}))`), e
   exige `cr recomputado == cr on-chain`. Isto prova a integridade do **conjunto ancorado**:
   omitir um evento muda o `events_root`, muda o `cr`, e não bate. Âncoras legadas (CID puro)
   mostram "CID puro" nesse passo.

## O que ele **ainda não** prova (limites honestos)

Este verificador expõe as fraquezas em vez de escondê-las:

- **O snapshot ancorado é ponto-no-tempo.** O passo 4 prova o **conjunto da época da
  ancoragem**. Eventos criados **depois** só entram sob commitment on-chain quando a âncora
  é reescrita (`cid_update` por evento — trabalho em aberto). O CLI exibe essa defasagem.
- Não verifica as **leituras cruas privadas** (só o snapshot público) nem a **assinatura
  ed25519 do snapshot** (a chave é publicada pela DeFarm; ancoragem externa da chave é
  trabalho em aberto).

Esses limites são reais e o roadmap da DeFarm os fecha (re-ancoragem por evento, carimbo de
tempo ICP-Brasil — ver `defarm_act.py` abaixo —, ancoragem da chave de assinatura). Até lá,
este CLI diz a verdade sobre o que a prova cobre.

## A terceira testemunha: carimbo de tempo RFC 3161 (`defarm_act.py`)

A âncora on-chain (Stellar) prova **anterioridade pública**: aquele conteúdo existia quando o
ledger fechou. Um **carimbo de tempo RFC 3161** de uma Autoridade de Carimbo do Tempo (TSA)
acrescenta uma testemunha **independente** da blockchain — e, com uma ACT credenciada
**ICP-Brasil**, uma data com **presunção legal** no Brasil (MP 2.200-2/2001).

O desenho não carimba cada evento (custo variável). Carimba, **1 vez por dia**, uma **Merkle
root SHA-256** das `content_root` confirmadas do dia (a `daily_root`); a prova de inclusão liga
o `content_root` de cada item a essa root carimbada. Uma root, três testemunhas: a blockchain,
o IPFS, e a TSA.

`defarm_act.py` é a **referência + o verificador** desse mecanismo. Ele cria e confere um
carimbo RFC 3161 sobre uma root, usando **só o padrão** (via `openssl ts`), não um validador
proprietário — é o que um terceiro roda para validar a terceira testemunha sem a DeFarm:

```bash
# conferir um carimbo já emitido (o que um cético faz), 100% offline:
python3 defarm_act.py --root-hex <sha256-da-daily-root> --token carimbo.tsr \
    --ca cacert.pem --tsa-cert tsa.crt

# provar o mecanismo ponta a ponta contra uma TSA pública (FreeTSA):
python3 defarm_act.py --root-hex <sha256-hex> --tsa https://freetsa.org/tsr \
    --ca-url https://freetsa.org/files/cacert.pem --tsa-cert-url https://freetsa.org/files/tsa.crt
```

A verificação confere: (1) o `messageImprint` do token é **exatamente** a `daily_root` — trocar a
root reprova com *message imprint mismatch*; (2) a assinatura do token encadeia até a CA da TSA;
(3) o `genTime` é a data atestada. O protocolo é idêntico na FreeTSA (teste) e numa ACT ICP-Brasil
(produção) — muda só a cadeia de certificados. Requisito: `openssl` no PATH.

### A prova completa: o manifesto do lote (o que roda em produção)

Na prática o carimbo diário publica um **manifesto** no IPFS (`defarm.act_timestamp_batch.v1`) com
as folhas do dia + o token embutido. Um terceiro baixa o manifesto e roda **uma prova órfã de uma
tacada**:

```bash
python3 defarm_act.py --manifest lote.json --ca cacert.pem --tsa-cert tsa.crt
```

Isto faz, sem a DeFarm: (1) **recusa cedo** se o `root_alg`/`leaf_schema` forem desconhecidos (não
recalcula uma árvore que não sabe reproduzir); (2) **recompõe a `daily_root`** das folhas (o mesmo
Merkle-SHA256 do servidor) e confere == a root declarada — trocar uma folha muda a root e reprova;
(3) **verifica o carimbo** sobre a root. O veredito é único: "as N content_roots do dia estão
carimbadas em `<genTime>` — recomposto e verificado sem a DeFarm".

> **`-digest`, não `-data`.** A `daily_root` já é um SHA-256 (é o próprio imprint), então a
> verificação usa `openssl ts -verify -digest <root>`; um `-verify -data` re-hashearia a root e
> reprovaria. Este é o modo do desenho do C2, e o que o `--manifest` faz por baixo.

## O carimbo de tempo das ASSINATURAS (`defarm_sig_ts.py`) — N1 D3

A mesma testemunha de tempo, agora sobre as **assinaturas anexadas** (não sobre a `content_root`):
cada assinatura verificada do dia vira uma folha, as folhas formam uma `signature_root` (a **mesma
árvore** Merkle-SHA256, outro `root_domain`), a root é carimbada 1×/dia por uma TSA. O `/verify`
publica, por assinatura, um `trusted_timestamp` (estado + prova de inclusão + o ACT).

`defarm_sig_ts.py` é o **canário**: pega um `/verify` e, para cada assinatura, prova sem a DeFarm —

1. recompõe o `leaf_hash` **só** dos campos publicados e confere == `proof.leaf_hash` (byte-exatidão);
2. sobe a `inclusion_proof` (position+siblings) até `proof.root_hash_sha256` (esta folha está na root);
3. baixa o manifesto no IPFS (`proof.act.timestamp_token_cid`), recompõe a root inteira das folhas e
   **verifica o carimbo RFC 3161** (`openssl ts -verify -digest`, cadeia até a CA — a mesma prova do
   `defarm_act.py`, reusada); e confere que a root do `/verify` == a root do manifesto.

```bash
# de um /verify já baixado (reproduzível, sem re-tocar a API):
python3 defarm_sig_ts.py --verify-json verify.json

# de uma URL, em modo JSON (para um cron/monitor):
python3 defarm_sig_ts.py --verify-url https://.../api/verify/<DFID> --json
```

> **Alarme, não silêncio.** Uma assinatura `materialized_pending_stamp` há **mais** que
> `--max-pending-days` (default 3 = margem + cadência diária + folga) não é pendência normal — é um
> dia que **não carimbou** (worker parado, ou a margem subida em produção). O canário **sai `!= 0`**
> nesse caso, para um monitor gritar em vez de "pendente há 3 dias" parecer normal.

> **Propagação ≠ defeito.** Logo após carimbar (fluxo one-shot), o `/verify` já diz `timestamped` mas
> o manifesto recém-pinado leva **minutos** para resolver num gateway IPFS público. A prova de inclusão
> **já fecha só com o JSON** (leaf + siblings), então o canário reporta `verified_pending_manifest`
> (`✓ incluída na root`) e **NÃO sai `!= 0`** — o último elo (recompor a root inteira + `openssl`) é um
> **retry**, não um alarme. Um canário que grita por propagação vira ruído. Para exigir o manifesto
> recuperável AGORA (canário estrito, rodado depois da propagação), passe `--require-manifest`.
>
> **Ressalva — o transiente tem TETO.** Propagação é minutos; um manifesto inalcançável há **mais** que
> `--max-pending-days` **não** é propagação, é **pin perdido** → o canário reporta `stale_pending_manifest`
> e **sai `!= 0`** (senão "pendente para sempre" repete o silêncio no último elo). A idade é a do **PIN**
> (`proof.act.issued_at`, o genTime do carimbo), NÃO a do anexo — um pin de 7 s de uma assinatura
> antiga (backfill/replay) segue transiente, não vira falso alarme.

## Uso

```bash
pip install -r requirements.txt        # blake3 + certifi + rfc8785
python3 defarm_verify.py DFID-BEEF-BR-2026-001179-9e3fe8
```

Saída: três passos com ✓/✗, os valores on-chain (DFID, CID, data), e um veredito. Código
de saída `0` = tudo confere, `1` = algo não bate, `2` = não deu pra verificar (sem âncora,
sem rede).

### Independência total (sem tocar na API da DeFarm para a âncora)

Por padrão o CLI busca o `tx_hash` inicial via `/verify` da DeFarm — mas apenas como
**ponteiro**: ele confirma esse `tx_hash` no Horizon e checa que o DFID on-chain bate. Se
você já tem o `tx_hash` (do link do explorer na página), passe-o e o passo da âncora não
toca a DeFarm:

```bash
python3 defarm_verify.py <DFID> --tx <tx_hash>
```

Opções: `--api`, `--horizon`, `--ipfs-gateway` (repetível), `--no-color`.

## Como funciona (para auditar)

- `onchain_from_horizon` — `GET {horizon}/transactions/{tx}`, `base64`-decode do
  `envelope_xdr`, e um regex acha o commitment `{"d":"<DFID>","ipfs":"<CID>",...}` embutido
  nos argumentos da chamada de contrato (não é preciso decodificar SCVal do Soroban).
- `fetch_snapshot` — `GET {gateway}/{cid}` em vários gateways, exige bytes idênticos.
- `recompute_content_hash` — reproduz o hash canônico do backend. `sort_keys=True`,
  separadores `(",", ":")`, `ensure_ascii=False`; o `json` do Python preserva int vs float
  (`390` vs `390.0`), então bate byte-a-byte com o `serde_json` do servidor.

Uma dependência fora da stdlib: [`blake3`](https://pypi.org/project/blake3/) (o hash) e
`certifi` (CA bundle, para o TLS funcionar no macOS). Tudo o mais é stdlib.

## Licença

MIT. Veja [LICENSE](LICENSE).
