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

## O que ele **ainda não** prova (limites honestos)

Este verificador expõe as fraquezas em vez de escondê-las:

- **O snapshot ancorado é ponto-no-tempo.** Ele compromete um `events_root` da época da
  ancoragem. Eventos criados **depois** não estão sob nenhum commitment on-chain (a âncora
  não é reescrita a cada evento novo). A integridade do passo 3 é do *conteúdo de cada
  evento*, não prova de que o **conjunto atual** está ancorado.
- Não há um `content_root` on-chain além do CID; a recomputação do `events_root` histórico
  exigiria o conjunto exato de eventos da época (que o snapshot não lista individualmente).
- Não verifica as **leituras cruas privadas** (só o snapshot público) nem a **assinatura
  ed25519 do snapshot** (a chave é publicada pela DeFarm; ancoragem externa da chave é
  trabalho em aberto).

Esses limites são reais e o roadmap da DeFarm os fecha (commitment on-chain por conjunto,
carimbo de tempo ICP-Brasil, ancoragem da chave de assinatura). Até lá, este CLI diz a
verdade sobre o que a prova cobre.

## Uso

```bash
pip install -r requirements.txt        # blake3 + certifi
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
