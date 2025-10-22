# Branch protection and PR workflow

Follow these steps on GitHub to protect the `main` branch and require reviews and passing checks before merge:

1. Go to Settings -> Branches -> Branch protection rules -> Add rule
2. Set `Branch name pattern` to `main`
3. Check `Require a pull request before merging`
4. Check `Require status checks to pass before merging` and choose the CI workflow checks (`CI / build`)
5. Optionally enable `Require approvals` and set required number of reviewers to 1 or 2
6. Optionally enable `Include administrators` to enforce rules for repo admins as well

When set, every PR to `main` will need the above conditions satisfied before merging.
