# Chain and client qualification

`zdn` creates an isolated Zcash Testnet. Ironwood is the shielded payment pool
enabled on that chain. lightwalletd is the optional external light-wallet service.
A separate wallet backend holds keys, scans notes, creates proofs, and signs.

**ZDN CLI payments use a separate Ironwood wallet program; Vizor and Zodl
have not yet been tested with ZDN.** See the [first-payment walkthrough](wallet.md#first-payment-alice-and-bob)
for local independent Alice/Bob wallets, reward funding, receipt checks and Bob's
later spend. It uses private full-node RPC, not a third-party wallet app or
lightwalletd. A successful guide, service startup or reachable RPC endpoint is
not evidence of app compatibility.

The [source compatibility review](lightwalletd-compatibility.md) selects lightwalletd
v0.5.5 and protocol v0.5.0 as candidates with Ironwood fields and v6 parsing.
The [diagnostic adapter](lightwallet.md)
checks compact data and trees against node observations. These version selections
do not qualify Vizor, Zodl or another app. Apps must support this exact custom
chain, Ironwood payment pool, activation schedule and private connection path;
stock Mainnet/Testnet support is not sufficient.

The offline CLI emits a **chain request**, not a launch-ready chain manifest.
It expands the requested activation schedule through NU6.3 and keeps missing
network identity, genesis, subsidy, difficulty, client versions, and funding
recipe visible. No supported release image or wallet version is invented.
The CLI has no qualified release catalog yet. An exact `--release` value records
a candidate to qualify; it does not establish support.

`chain inspect` separately checks a candidate [consensus manifest](chain-manifest.md)
and computes its normalized fingerprint. The command does not generate or verify
genesis/seed bytes, produce node configuration, or qualify any client. Its
fingerprint is not interchangeable with the draft chain request hash below.

`chain import` and `chain verify` separately check [saved byte bundles](chain-artifacts.md)
against that consensus manifest. Matching SHA-256 digests and lengths do not
establish decoded block identities, a valid chain, or client compatibility.

`chain render-config` maps supported manifest settings to a candidate
[Zakura network TOML fragment](node-config.md). The command does not invoke the
node parser or validate effective rules, funding periods, or block history.
It always keeps node validation and launch readiness false.
`chain render-runtime` adds [candidate runtime settings](runtime-config.md) and
startup arguments with the same pending flags. [Bootstrap and readiness](bootstrap-readiness.md)
use authenticated node diagnostics, verifier-backed loading, and best-chain
observations. These commands do not qualify a chain recipe, payment path, or client.

The compatibility record binds component artifact hashes, required capabilities,
and a human evidence report to the chain request hash. Structural validation
checks completeness. It cannot authenticate a report or establish that a real
payment succeeded. Deployment must consume a reviewed complete manifest and
accepted evidence, not promote a draft request automatically.

## Choose matching components

Use the reviewed node source/image, manifest and saved block bundle together.
For CLI payments, also obtain the separately trusted wallet source/build,
matching notices and independently verified executable SHA-256 described in
[wallet setup](wallet.md#1-obtain-the-matching-wallet-program). The crate's
`0.1.0` label alone does not identify compatible wallet bytes. The referenced
backend uses Common 3.0.0 and the NU6.3-at-height-1/no-NU7 custom-Testnet recipe;
it is not a general-purpose wallet for arbitrary network configurations.

Network-management packages do not establish the availability or compatibility
of an optional wallet download. Check the selected release's actual contents and
installation limitations. Keep keys local and use the original complete wallet
store for spending/recovery; importing a bare key creates a scan-only wallet.

Private CLI payments do not require lightwalletd. Optional lightwalletd and
external wallet apps have separate transport/protocol requirements, including
real-device access rather than an assumed desktop loopback route. See
[lightwallet setup](lightwallet.md) and the [test inventory](testing.md) for the
separate checks; ordinary offline tests do not run live payments or establish
external-app support.

Protocol references: [NU6.3 and Ironwood](https://zips.z.cash/zip-0258),
[wallet consequences](https://zips.z.cash/zip-0326), and
[lightwalletd](https://github.com/zcash/lightwalletd).
