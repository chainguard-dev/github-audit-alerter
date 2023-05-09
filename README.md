# github-audit-alerter

Send Slack alerts based on GitHub Audit Events, including two major categories of events:

* Excessive repository clones by a single user
* Unexpected events, such as a private repository being made public

This is chiefly to detect whether or not someone's Github credentials have been abused for nefarious purposes, but can be used to notify on secrets shared on repos unintentionally made public.

## Requirements

go v1.20.0 or newer

## Usage

You will need a GITHUB_TOKEN with permissions where the `Resource owner` is the organization you are testing. 

For this You can go and [create a new PAT](https://github.com/settings/personal-access-tokens/new) and select `Permissions / Organization Permission / Administration (Manage access to an organization.)` and set it to `Access: read-only`. That is the only permission you need.

Testing:

```
export GITHUB_TOKEN=$(cat <your-github-token-file>)
github-audit-alerter --org chainguard-dev --max-repos-cloned-per-user=3
```

To send Slack events, set the GH_AUDIT_SLACK_WEBHOOK environment variable.
