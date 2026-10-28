<!--
Use a Conventional Commit title: type(optional-scope): summary.
Keep the description proportional to the change and delete inapplicable sections.
Do not include credentials, wallet data, private receipts or personal email addresses.
-->

## Motivation

<!-- Describe the goal and why this change is needed. For fixes, identify the root cause. -->

## Solution

<!-- Explain the approach and how it addresses the problem. Note important tradeoffs. -->

## Testing

<!--
- List exact commands and outcomes, and explain how they exercise the affected behavior.
- For code changes, use the relevant checks from docs/testing.md:
  cargo fmt --all -- --check
  cargo test --locked
  cargo clippy --all-targets --locked -- -D warnings
- For documentation-only changes, check links, command syntax and git diff --check.
- Mark unrun checks pending with a reason. Separate local-fixture results from live evidence.
- Heavy validation (AWS, node/container builds, proofs, performance) requires explicit approval;
  a PR or request to test is not approval. Record the approved scope if such checks ran.
-->

## Risks and compatibility

<!--
Describe any CLI/configuration changes, IAM permissions, secret handling, persistent-state
changes, AWS costs or recovery/removal implications. Explain migration or rollback needs.
-->

## References and follow-up

<!-- Link related issues/specifications and identify remaining work or known limitations. -->
