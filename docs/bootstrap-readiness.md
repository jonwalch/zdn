# Load saved history and check a running node

`chain bootstrap` loads saved genesis/seed bytes through an existing node's
verifier. `chain readiness` checks its parsed rules and actual best-chain history.
Neither command starts a node, creates AWS resources, or starts block production.

These are advanced commands for an existing node. Normal [network launch](preview-start.md)
loads and checks history automatically; do not repeat bootstrap manually on a
running deployment to bypass lifecycle recovery.

These commands require a Zakura build with the authenticated `getchainrules` and
`inspectchainblock` diagnostics. An older node fails before block submission.
Use the running node's cookie file and a numeric loopback RPC endpoint, directly
or through an existing private tunnel. The transport rejects public addresses,
redirects, environment proxies, and cookies readable by other users.

```sh
zdn chain bootstrap --manifest candidate-chain.json --bundle chain.tar \
  --rpc-endpoint 127.0.0.1:18232 --cookie-file /private/path/.cookie \
  --producer-stopped

zdn chain readiness --manifest candidate-chain.json \
  --rpc-endpoint 127.0.0.1:18232 --cookie-file /private/path/.cookie \
  --role producer
```

Keep every external producer stopped during loading. `--producer-stopped` records
that precondition; it does not stop a process or acquire a distributed lock.
Unexpected observed tip changes fail the load. Each restarted command reads
actual state again rather than trusting a saved progress receipt.

Both commands accept `--request-timeout-secs` (default 10, maximum 60) and
`--deadline-secs` (default 120, maximum 3600). Each request is capped by the
remaining deadline. RPC bodies are limited to 8 MiB. Errors omit cookie contents
and remote error text. Bootstrap and readiness each read the cookie once; rerun
those commands after a node restart that rotates it.

Before loading a starting node, use `chain wait-rpc` with the same `--manifest`,
`--rpc-endpoint`, and `--cookie-file` options. It reloads the cookie on each
attempt and retries a missing cookie, transport failure, or HTTP 401 within
`--deadline-secs`. It reads only `getchainrules` and requires matching effective
rules. Unsafe cookies, other RPC/protocol errors, and mismatched rules fail
immediately. Success establishes RPC availability, not history, mining, or
payment readiness. The EC2 host runner uses this gate with a 60-second deadline
before bootstrap and observation.

## Supported loading recipe

The first loader requires contiguous saved blocks from genesis through the seed
tip, with a matching checkpoint at **every saved height**, and no later checkpoint.
Genesis alone is supported. It rejects sparse checkpoints or seed blocks above
the final checkpoint before any RPC request. It never adds checkpoints or changes
the manifest's trust policy to make loading succeed.

This restriction permits serial replay without waiting for a later checkpoint
span. Bounded concurrent spans and semantic replay need separate supported recipes.

The loader performs these steps:

1. Verify the entire canonical bundle in one pass and retain exactly the verified
   bytes. Existing bundle count and memory limits still apply.
2. Compare the expected rules with the node-owned `getchainrules` result.
3. Use `inspectchainblock` to decode every saved block before submitting any.
   Check canonical length, height, hash, and parent linkage. Structural decoding
   does not establish consensus validity.
4. Observe saved heights and the actual tip with `getblockhash`. Require matching,
   contiguous history and an expected tip. Preserve the existing database.
5. Submit missing blocks through `submitblock`. Verify the expected best-chain
   hash and parent before advancing. A null success, duplicate, inconclusive
   response, or lost reply does not establish best-chain acceptance.
6. Re-observe before retrying; a commit can finish after its RPC times out.
   Limit submissions to three attempts per block and the total deadline.
7. Recheck effective rules, complete saved history, and the final tip.

If `submitblock` returns the literal `rejected`, a peer may have verified the same
checkpoint while its state commit is still pending. The loader allows up to
three delayed observation rounds for the exact block, parent, and tip. It never
resubmits after that rejection in the same loading run. Persistent absence or a
conflict fails the load.

Height and tip reads are separate RPCs. If a missing height is followed by an
expected saved tip, the loader allows up to three consistency retries and must
observe the exact contiguous prefix again. A matching tip alone is insufficient.
All reconciliation stays within the total deadline; rules and hashes remain
mandatory.

Reports include manifest/bundle hashes, observed/submitted counts, and
`seedHistoryPresent`. They report `checkpointAcceptance: true` and
`fullSemanticValidation: false`: checkpoint trust does not run every historical
transaction/proof check. `qualification` remains `pending` and `launchReady`
remains false. A failure can leave a verified prefix committed; retry against
the same manifest and bundle to reconcile it.

## Readiness observations

The default `--role follower` checks effective rules, every declared saved block
and checkpoint, the actual tip, and upgrade/branch fields. It repeats history,
tip, and rule observations before returning. `getblockchaininfo` alone cannot
prove genesis presence because it can return a configured-genesis fallback.

`--role producer` also requires disabled PoW and a fresh, non-long-poll template
whose parent and next height match the observed tip. A template can contain no
transactions while the mempool is inactive. `miningReady` is separate from payment
or transaction readiness; it does not establish successful generation or
Ironwood payments.

A report is a bounded observation, not a lock against a later reorg, restart,
or configuration change. The [block controller](block-producer.md) rechecks before
starting its schedule and before each generation request. Stale observations and temporary transport failures retry
within the deadline; wrong rules, conflicting hashes, malformed replies, and
authentication failures stop immediately. Payment qualification stays pending
and `launchReady` stays false.

## Node contract and qualification

`getchainrules` reports parsed network magic, genesis, checkpoints, effective
upgrade heights, subsidy/funding/lockbox/NSM policy, difficulty/PoW policy, the
Orchard rule, and explicit experiment state. The schema is
`zakura-chain-rules/v1`; fixed protocol semantics use
`zakura-configured-testnet/v1`. It does not echo a requested fingerprint.

`inspectchainblock` uses the node's decoder, canonical serializer, and hash
calculation. Its schema is `zakura-block-inspection/v1`. Both diagnostics require
authenticated admin access. Unsupported network/rule types fail closed.

Fast tests use scripted RPC, fake clocks, independent wire fixtures, loopback
HTTP, and temporary files. They cover wrong rules/history, empty-state fallbacks,
stale templates, delayed commits, missing replies, restart observations, cookie
handling, redirects, and deadlines. No node dependency is added to the CLI.

See [private node deployment](private-devnet.md) for lifecycle contracts.
Scheduled generation, later joining peers with empty databases, and the
[wallet/lightwalletd checks](compatibility.md)
remain separate qualification work. A successful bootstrap is not a release
qualification.
