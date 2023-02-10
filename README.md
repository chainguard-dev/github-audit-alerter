# github-audit-alerter

*As of Feb 10, 2023 - UNDER HEAVY DEVELOPMENT*

Send Slack alerts based on GitHub Audit Events, including two major categories of events:

* Excessive repository clones by a single user
* Unexpected events, such as a private repository being made public

This is chiefly to detect whether or not someone's Github credentials have been abused for nefarious purposes.

## Requirements

go v1.20.0 or newer

## Usage

```
github-audit-alerter --org chainguard-dev --max-repos-cloned-per-user=3
```
