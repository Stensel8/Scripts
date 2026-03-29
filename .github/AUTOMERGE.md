# Automerge and Branch Cleanup Documentation

This document describes the automatic PR approval, merge, and branch cleanup workflows in the Scripts repository.

## Overview

The repository includes two workflows that automate the lifecycle of Pull Requests created by trusted automation:

1. **Automerge Workflow** (`.github/workflows/automerge.yml`) - Automatically approves and enables automerge for PRs
2. **Auto Delete Branch Workflow** (`.github/workflows/auto-delete-branch.yml`) - Automatically deletes branches after PRs are merged

## Automerge Workflow

### Purpose

Automatically approves and enables automerge for Pull Requests created by trusted automation sources, reducing manual overhead while maintaining quality control.

### Triggers

- **Automatic**: When a PR is opened, reopened, or marked ready for review
- **Manual**: Via workflow dispatch with a PR number input

### Eligible PRs

A PR is eligible for automerge if it meets ALL of the following criteria:

1. **Created by trusted automation**:
   - Author is `Claude` (Anthropic AI agent)
   - Author is `github-actions[bot]`
   - Branch name starts with `automated-update/`
   - Branch name starts with `claude/`

2. **Not a draft PR**: Draft PRs are skipped

3. **All checks passed**: All required status checks must pass

### Behavior

1. **Check Eligibility**: Verifies the PR meets automerge criteria
2. **Approve PR**: Automatically approves the PR with a standardized message
3. **Enable Automerge**: Uses GitHub's automerge feature with squash merge method
4. **Error Handling**: Comments on the PR if automerge fails

### Configuration

The workflow uses the following merge method:
- **Default**: `SQUASH` - Combines all commits into a single commit

To change the merge method, edit line 124 in `.github/workflows/automerge.yml`:
```yaml
mergeMethod: 'SQUASH'  # Options: MERGE, SQUASH, REBASE
```

### Permissions Required

- `contents: write` - To enable automerge
- `pull-requests: write` - To approve PRs and add comments

## Auto Delete Branch Workflow

### Purpose

Automatically cleans up branches after their Pull Requests are merged, keeping the repository tidy and preventing branch accumulation.

### Triggers

- **Automatic**: When a PR is closed (only deletes if merged)
- **Manual**: Via workflow dispatch with a branch name input

### Protected Branches

The following branches are NEVER deleted:
- `main`
- `master`
- `development`
- `staging`
- `production`

### Behavior

1. **Verify Merge**: Confirms the PR was actually merged (not just closed)
2. **Check Protection**: Ensures the branch is not in the protected list
3. **Delete Branch**: Removes the branch from the repository
4. **Add Comment**: Posts a comment on the PR confirming deletion
5. **Error Handling**: Gracefully handles cases where the branch doesn't exist

### Fork Handling

Branches from forked repositories are NOT deleted, as the workflow only has permissions in the main repository.

### Permissions Required

- `contents: write` - To delete branches

## Integration with Existing Workflows

### Auto-Update Dependencies Workflow

The automerge workflow works seamlessly with the existing dependency update automation:

1. `check-dependencies.yml` creates an issue when a new version is detected
2. `auto-update-dependencies.yml` creates a PR to update the dependency
3. **NEW**: `automerge.yml` automatically approves and enables automerge
4. GitHub merges the PR when all checks pass
5. **NEW**: `auto-delete-branch.yml` deletes the branch after merge
6. The original issue is automatically closed via `Closes #XX` in PR body

### Dependabot PRs

Dependabot PRs are also eligible for automerge if:
- They pass all status checks
- The workflow approves them automatically

To disable automerge for Dependabot PRs, you can modify the eligibility check in `automerge.yml`.

## Manual Intervention

### When Manual Review is Required

Certain PRs require manual review and will NOT be automatically merged:

1. **NGINX Updates**: Marked as draft until SHA256 checksums are manually verified
2. **PRs from untrusted sources**: Only automation from trusted sources is auto-merged
3. **Failed checks**: PRs with failing status checks must be fixed before merge

### Manual Workflow Triggers

Both workflows support manual triggering:

#### Enable Automerge for a Specific PR
```bash
gh workflow run automerge.yml -f pr_number=123
```

#### Delete a Specific Branch
```bash
gh workflow run auto-delete-branch.yml -f branch_name=my-feature-branch
```

## Monitoring and Troubleshooting

### View Workflow Runs

Check workflow execution in the GitHub Actions tab:
```
https://github.com/Stensel8/Scripts/actions
```

### Common Issues

#### Automerge Not Enabled

**Possible causes**:
1. Repository settings don't allow automerge
2. Branch protection rules require additional approvals
3. PR is from an untrusted source
4. Status checks are failing

**Solution**: Check the workflow logs and verify repository settings.

#### Branch Not Deleted

**Possible causes**:
1. PR was closed without merging
2. Branch is in the protected list
3. Branch is from a fork
4. Branch was already deleted

**Solution**: These are expected behaviors. Check the workflow logs for details.

## Security Considerations

### Trusted Sources

The workflows only operate on PRs from:
- `Claude` (Anthropic AI agent)
- `github-actions[bot]`
- Branches matching specific patterns

This prevents unauthorized users from triggering automerge on malicious PRs.

### Required Checks

Automerge only enables if all required status checks pass, ensuring:
- Code validation (ShellCheck, PSScriptAnalyzer)
- Security scanning
- Any other configured checks

### Approval Trail

All auto-approved PRs include a comment indicating they were automatically approved, maintaining an audit trail.

## Disabling the Workflows

To temporarily disable automerge or branch cleanup:

1. **Via GitHub UI**: Go to Actions → Select workflow → Disable workflow
2. **Via Code**: Add `if: false` to the job in the workflow file

Example:
```yaml
jobs:
  automerge:
    name: Enable Automerge
    runs-on: ubuntu-latest
    if: false  # Temporarily disable
```

## Future Enhancements

Potential improvements for consideration:

1. **Merge Method Selection**: Different merge methods based on PR type
2. **Approval Requirements**: Configurable approval count before automerge
3. **Label-Based Control**: Use labels to enable/disable automerge per PR
4. **Notification System**: Slack/Discord notifications for automated merges
5. **Rollback Mechanism**: Automatic revert if merged PR causes issues

## Related Documentation

- [Auto-Update Dependencies Workflow](../workflows/auto-update-dependencies.yml)
- [Check Dependencies Workflow](../workflows/check-dependencies.yml)
- [GitHub Automerge Documentation](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/incorporating-changes-from-a-pull-request/automatically-merging-a-pull-request)
- [GitHub Branch Protection Rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
