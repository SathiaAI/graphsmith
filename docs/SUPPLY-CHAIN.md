# GraphSmith Supply Chain Model

## Trust Boundary Overview

This document describes the trust model and supply-chain security posture for GraphSmith, specifically for the GitHub Action (`action.yml`) and GitLab CI template (`templates/graphsmith.gitlab-ci.yml`) that wrap `graphsmith verify`.

## Core Principles

1. **SHA Pinning Only**: All third-party GitHub Actions are pinned by full commit SHA, never tags
2. **No Secret Exposure on PR Triggers**: Secrets are never available on pull_request workflows
3. **No `pull_request_target`**: This workflow never uses the elevated permissions of `pull_request_target`
4. **Consumer SHA Pinning**: Downstream repos MUST pin GraphSmith itself by full commit SHA
5. **Read-Only Permissions**: Actions only request `contents: read` unless explicitly needed for release flows

## GitHub Action Trust Model

### Third-Party Action Pinning

The following third-party actions are used with explicit commit SHA pinning:

- `actions/checkout@11d5960a326750d5838078e36cf38b85af677262` (v4.4.0)
- `actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020` (v4.4.0)

These SHAs are taken directly from the existing `.github/workflows/ci.yml` file to ensure consistency across the GraphSmith codebase.

### Permissions Model

The action uses minimal permissions:
```yaml
permissions:
  contents: read
```

This is enforced at both the workflow level (in downstream repos) and within the composite action itself. The action never requests write permissions, secrets access, or other elevated permissions.

### No `pull_request_target`

The action is intentionally designed to work with the standard `pull_request` trigger, not `pull_request_target`. This means:
- The action runs with the permissions of the PR author
- No secrets are available (since PRs from forks cannot access repo secrets)
- This is a safe default for verification workflows that only need to read code

### Consumer Requirements

Downstream repos using this action MUST:

1. Pin by full commit SHA, never a tag:
   ```yaml
   uses: SathiaAI/graphsmith@11d5960a326750d5838078e36cf38b85af677262
   ```
   
2. Never use:
   ```yaml
   uses: SathiaAI/graphsmith@v1.0.0  # FORBIDDEN
   uses: SathiaAI/graphsmith@main     # FORBIDDEN
   ```

3. Configure branch protection to require the GraphSmith verification status check as a required check for merge

## GitLab CI Template Trust Model

### Image Pinning

The template uses `image: node:20`, which refers to a specific Docker tag. For additional security, downstream users may want to pin to a specific digest:
```yaml
image: node:20@sha256:<specific_digest>
```

### Verification Logic

The GitLab CI template implements the same verification logic as the GitHub Action:
- unavailable profiles are annotated but do NOT fail the build
- failed profiles DO fail the build
- The fail-on behavior can be configured via the `GRAPHSMITH_FAIL_ON` variable

### Consumer Requirements

Downstream repos using this template MUST:

1. Include by full commit SHA, never a tag:
   ```yaml
   include:
     - project: 'SathiaAI/graphsmith'
       ref: 11d5960a326750d5838078e36cf38b85af677262
       file: 'templates/graphsmith.gitlab-ci.yml'
   ```

2. Never use:
   ```yaml
   include:
     - project: 'SathiaAI/graphsmith'
       ref: v1.0.0  # FORBIDDEN
       ref: main    # FORBIDDEN
   ```

## Verification Profiles and Status Semantics

The `graphsmith verify --profiles` command outputs a JSON structure with profile statuses. The action interprets these as follows:

### Profile Status Types

- **`verified`**: The profile check passed successfully. This is the success state.
- **`failed`**: The profile check failed. This ALWAYS fails the build.
- **`unavailable`**: The profile cannot be checked (e.g., missing dependencies). This is annotated but does NOT fail the build by default.
- **`not-applicable`**: The profile is not applicable to the current context. This is annotated but does NOT fail the build.

### Failure Modes

The action supports a `fail-on` input to control behavior:

- **`unavailable-is-not-failure`** (default): unavailable profiles are annotated but do not fail the build
- **`unavailable-is-failure`**: unavailable profiles are treated as failures and fail the build

In all modes, `failed` profiles fail the build.

## Trust Root and Release Manifest

The trust root for GraphSmith is the release manifest (T-profile). This profile verifies:
- Package integrity and self-consistency
- Independent verification axes per contract 09
- No collapse of distinct trust dimensions

The T-profile is computed live from `--integrity` checks and provides the foundation for all other verification profiles.

## Assumptions and Limitations

### Assumptions

1. **GitHub/GitLab Infrastructure**: We assume the underlying GitHub Actions and GitLab CI infrastructure are secure and correctly implement the documented permission models.

2. **Action Registry**: We assume the GitHub Actions registry maintains the integrity of actions referenced by commit SHA.

3. **Docker Registry**: For GitLab CI, we assume the Docker Hub registry maintains the integrity of images referenced by tag/digest.

### Limitations

1. **No Runtime Dependency Verification**: The action does not verify the integrity of npm packages installed during the run, beyond what Node.js's built-in verification provides.

2. **No Network Security**: The action does not enforce network security policies or inspect outbound connections.

3. **No Code Signing**: The action does not verify code signatures for executables or binaries.

4. **PR Review Process**: The action provides automated verification but does not replace human code review processes.

5. **Supply Chain Depth**: This model secures the direct dependencies (third-party actions) but does not extend to transitive dependencies of those actions.

## Security Updates and Maintenance

When security vulnerabilities are discovered in third-party actions:

1. Update the pinned SHA in both `action.yml` and `.github/workflows/ci.yml`
2. Update this document to reflect the new SHA and version
3. Release a new version of GraphSmith with the updated pins
4. Communicate the update to downstream consumers

Downstream consumers should update their SHA pin when:
- New security patches are released
- New features are added that they need
- Deprecation notices are issued

## Compliance and Standards

This supply chain model is designed to align with:
- GitHub's security best practices for Actions
- GitLab's security guidelines for CI/CD
- Industry standards for supply chain security in CI/CD pipelines
- OpenSSF Supply Chain Security Model

## Verification

To verify this implementation, run:
```bash
node scripts/verify.js --profiles
```

The output should show the current status of all verification profiles, demonstrating the live computation of trust information.