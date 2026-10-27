# zdn

This is an independent Rust workspace and local Git repository. Do not add node,
wallet-proof, or research-workspace dependencies. Do not publish this repository
without an explicit user request. Keep code and tests focused on the delivery plan.

Normal checks are `cargo fmt --all -- --check`, `cargo test --locked`, and
`cargo clippy --all-targets --locked -- -D warnings`. The test suite must use only
local fixtures, Git, temporary files/processes, and loopback servers. No AWS
credentials, Docker, live nodes, downloads, or proof generation may be required.

Real node/container builds, CodeBuild node jobs, live wallet/node validation,
proof fixture generation, and performance workloads require explicit user
approval before agent execution. Explain the exact commands, scope and reason
for the run, then ask for approval and wait before starting. Approval already
given in the conversation remains valid for its approved scope; do not ask again
for the same run. General requests to implement, review or test a change are not
explicit approval for heavy validation. Record unapproved or declined runs as
pending, with the reason.

The same approval requirement applies to wrappers, background jobs, delegated
agents and manual CI dispatch or reruns. Existing automatic CI is exempt; do not
change its triggers to bypass approval. References in older documentation to
"human-only" validation use this approval requirement for future agent-run
workloads; historical reports retain their original execution scope and results.
Unimplemented cloud commands must fail before making changes; never report
simulated cloud or payment success.

Defaults: Zakura only, isolated custom Testnet, Ironwood payment pool,
lightwalletd planned with compatibility unqualified, 25-second block target,
private access, three medium nodes, AWS/EC2/Docker, Pulumi with team-owned S3 state.
