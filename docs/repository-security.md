# Repository Security Settings
# Core Dev: apply these settings at
# https://github.com/NeaBouli/prometheus-/settings/branches

## Branch Protection Rules for "main"

Enable the following in GitHub Settings -> Branches -> Add rule:

Branch name pattern: main

- [x] Require a pull request before merging
  - Required approvals: 1
  - Dismiss stale pull request approvals: YES

- [x] Require status checks to pass before merging
  - Status checks: CI (from ci.yml)

- [x] Require conversation resolution before merging

- [x] Do not allow bypassing the above settings

- [x] Restrict who can push to matching branches
  - Add: NeaBouli (Core Dev)

## Additional Settings
GitHub Settings -> General:
- [x] Restrict forking: OFF (open source — forks allowed)
- [x] Allow merge commits: YES
- [x] Allow squash merging: YES
- [x] Automatically delete head branches: YES

GitHub Settings -> Code security:
- [x] Private vulnerability reporting: ENABLED
- [x] Dependabot alerts: ENABLED
- [x] Secret scanning: ENABLED

## What this prevents
- Direct pushes to main without review
- Merging when CI is red
- Accidental secret commits (API keys etc)
- Vandalism via force push
