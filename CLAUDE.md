# GitHub Actions cost rule (owner's standing rule)

GitHub Actions minutes are paid on private repositories, and a GitHub-hosted macOS minute costs 10 times a Linux minute. In November 2026 macOS runners were two thirds of the bill and the spending limit stopped a release build.

- **macOS jobs in private repositories run on the owner's own Mac**: `runs-on: [self-hosted, macOS, hanzala-mac]`. Never use `macos-latest`, `macos-26` or any other GitHub-hosted macOS runner there. The Mac must be on, with its runner running, when such a job starts.
- **Never use the self-hosted Mac in a public repository**, and never let it run code from a fork's pull request: anyone could then run code on the owner's computer. Public repositories use GitHub-hosted runners, which are free for them.
- Self-hosted jobs cannot use `sudo` (so no `setup-xcode`). Check required tools in an early step and fail with a clear message instead.
- Everything else runs on `ubuntu-latest`, and only when needed: limit `push` and `pull_request` triggers with `paths`, skip drafts, cancel superseded PR runs, and prefer `workflow_dispatch` for releases, deploys and one-off jobs. Never add `schedule` triggers without the owner's approval.
- Before adding or changing a workflow, say what it will cost per run.
