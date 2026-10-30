# ZDN documentation

ZDN starts private, disposable Zcash test networks in your AWS account. Begin
with the installation walkthrough; use the reference pages when you need a
specific command, recovery rule or advanced contract.

**Experimental preview:** no real funds or production AWS accounts. AWS costs
continue until resources are removed. Wallet files contain plaintext secrets.
Mac browser-download installation is blocked; see [current limits](preview.md).

## Start, use and remove a network

| Task | Guide |
| --- | --- |
| Understand ZDN | [Project overview](../README.md) |
| Install controller and separate wallet from source, free | [Manual and Homebrew source installation](install-source.md) |
| Install verified downloads and start one node | [First network](preview-start.md) |
| Check platform support, trust and preview limits | [Preview scope](preview.md) |
| Operate with an agent or machine-readable output | [CLI automation](automation.md) |
| Install prerequisites and managed tools | [Dependencies](dependencies.md) |
| Set up AWS access or recover setup | [AWS accounts and state](aws-state.md) |
| Launch, inspect or resume a network | [Deployment](private-devnet.md) |
| Connect an application or grant participant access | [Connections](connections.md) |
| Fund, send, back up and recover CLI payments | [Wallet](wallet.md) |
| Review the bounded transparent-payment AWS results | [Qualification and remaining limits](transparent-payments-validation.md) |
| Change a node image safely | [Updates](updates.md) |
| Remove participant grants, networks and teams | [Removal](removal.md) |
| Use optional lightwalletd | [Light-wallet setup](lightwallet.md), [client compatibility](compatibility.md) |

## Advanced reference

These pages explain contracts used by the normal lifecycle. They are not
additional installation steps. Standalone renderers validate their own inputs;
they do not establish a working network or a supported wallet.

| Area | Reference |
| --- | --- |
| Source and remote image builds | [Source capture](source-capture.md), [builds and recovery](builds.md) |
| Chain inputs | [Consensus manifest](chain-manifest.md), [saved block bytes](chain-artifacts.md) |
| Node configuration and startup | [Network configuration](node-config.md), [runtime configuration](runtime-config.md), [bootstrap/readiness](bootstrap-readiness.md) |
| Hosts and block production | [Host lifecycle](host-lifecycle.md), [block controller](block-producer.md), [private topology](private-topology.md) |
| Artifact identity and optional signed catalogs | [Image contract](image-contract.md), [packages](packages.md), [catalogs](releases.md) |
| State and infrastructure | [Local state](state.md), [Pulumi adapter](pulumi.md) |
| Optional infrastructure smoke test (no blockchain) | [Foundation](infrastructure.md), [foundation lifecycle](foundation-lifecycle.md) |
| Optional light-wallet service | [Service recipe](lightwallet-service.md), [compatibility status](lightwalletd-compatibility.md) |
| Timing, cost and diagnostic boundaries | [Deployment execution](deployment-performance.md), [operation tracing](profiling.md) |

## Contributors and source attribution

- Read [repository guidance](../AGENTS.md) before changing code or running validation.
- Use [testing](testing.md) for ordinary checks and separate live-workload approval rules.
- For a new Mac distribution, use the [signing and notarization runbook](macos-release.md).
  It is prepared, not executed or qualified; it does not fix Preview 2 downloads.
- The [pinned protocol README](../protocol/lightwallet-v0.5.0/README.md) records
  upstream wire definitions and their license/hashes.
- Synthetic [manifest](../tests/fixtures/chain-manifest/README.md) and
  [runtime](../tests/fixtures/runtime-config/README.md) fixtures are test inputs,
  not usable chains or payment evidence.
- Keep the matching source, source maps, licenses and notices from the selected
  release. Historical private-source identities are attribution, not installation
  prerequisites; see [source identities](preview.md#source-identities-and-notices).
