# CI/CD Integration

The repo includes two workflows:

- `ci.yml` for install + test
- `compliance-check.yml` for SARIF-producing compliance scans on pull requests

## PR scan flow

The compliance workflow:

1. installs the package locally
2. runs `guardrail scan . --format sarif --output results.sarif`
3. uploads SARIF to the GitHub Security tab
4. comments on the pull request when findings fail the build

Today the workflow defaults to `--no-bedrock` so it works without live Bedrock policy provisioning.
