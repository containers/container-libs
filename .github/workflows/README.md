# Downstream Repository Sync Workflow

This directory contains a GitHub Actions workflow that automatically creates pull requests in downstream repositories (buildah and podman) when changes are made to container-libs.

## Architecture

### Reusable Components

1. **Composite Action** (`.github/actions/sync-downstream/action.yml`)
   - Reusable action that handles the common sync logic
   - Parameterized to work with any downstream repository
   - Eliminates code duplication and enables easy addition of new repositories

### Unified Workflow

**Unified Workflow** (`opendownstream-pr-unified.yml`)
- Handles both buildah and podman repositories in parallel
- Uses the reusable composite action for consistent behavior
- Efficient execution with simultaneous syncs to both downstream repositories

## How It Works

1. **Trigger**: Activated on pull requests to the `main` branch that modify Go files (excluding tests and vendor)

2. **Process**:
   - Checkout the forked repository (podmanbot/buildah or podmanbot/podman)
   - Create a branch named `sync/container-libs-{PR_NUMBER}`
   - Update Go modules to use the PR's changes via replace directives
   - Run `go mod tidy` and `go mod vendor`
   - Commit and push changes
   - Create or update a draft PR in the upstream repository

3. **Output**: Comments on the original container-libs PR with links to created downstream PRs

