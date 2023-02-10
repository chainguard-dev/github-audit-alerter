package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/google/go-github/v50/github"
)

var (
	defaultAlertCategories = []string{
		"org",
		"oauth_application",
		"personal_access_token",
		"protected_branch",
		"environment",
		"repo",
		"repository_advisory",
		"repository_secret_scanning",
		"repository_vulnerability_alert",
		"repository_vulnerability_alerts",
		"role",
		"secret_scanning",
		"team",
		"workflows",
	}

	defaultIgnoreActions = []string{
		"environment.add_protection_rule",
		"org_credential_authorization.deauthorize",
		"org_credential_authorization.grant",
		"org.self_hosted_runner_online",
		"org.sso_response",
		"repo.pages_cname",
		"repo.pages_create",
		"repo.pages_private",
		"repo.pages_source",
		"repository_vulnerability_alert.dismiss",
		"repository_vulnerability_alert.resolve",
		"workflows.prepared_workflow_job",
		"workflows.cancel_workflow_run",
		"workflows.completed_workflow_run",
		"workflows.created_workflow_run",
		"workflows.rerun_workflow_run",
	}

	defaultIgnoreusers = []string{
		"github-actions[bot]",
		"dependabot[bot]",
		"vercel[bot]",
		"inky-ui-bot[bot]",
		"deploy_key",
		"chainguardian",
	}
)

var (
	dryRunFlag          = flag.Bool("dry-run", false, "dry-run mode")
	alertCategoriesFlag = flag.String("alert-categories", strings.Join(defaultAlertCategories, ","), "audit categories to watch")
	ignoreActionFlag    = flag.String("ignore-actions", strings.Join(defaultIgnoreActions, ","), "actions to ignore")
	ignoreUsersFlag     = flag.String("ignore-users", strings.Join(defaultIgnoreusers, ","), "ignore actions by these users")
	ignoreBotsFlag      = flag.Bool("ignore-bots", true, "ignore users ending with [bot]")
	webIntervalFlag     = flag.Duration("web-log-interval", 5*time.Minute, "How far to go backwards searching for actions to alert on")

	maxReposClonedFlag = flag.Int("max-repos-cloned-per-user", 3, "maximum repositories before creating a user alert")
	cloneIntervalFlag  = flag.Duration("clone-log-interval", 24*time.Hour, "How far to go backwards searching for git clone events to alert on")

	reposFlag = flag.String("repos", "", "only include these repositories")
	orgFlag   = flag.String("org", "", "Github Organization to query")
)

func auditString(a *github.AuditEntry) string {
	b, _ := json.Marshal(a)
	return fmt.Sprintf("%s", b)
}

func auditLog(ctx context.Context, c *github.Client, kind string, since time.Time) ([]*github.AuditEntry, error) {
	opts := &github.GetAuditLogOptions{
		Include: github.String(kind),
	}
	opts.ListCursorOptions.PerPage = 100
	as := []*github.AuditEntry{}

	log.Printf("querying %q audit events since %s", kind, since)
	logs, resp, err := c.Organizations.GetAuditLog(ctx, *orgFlag, opts)
	if err != nil {
		return as, err
	}

	for resp.After != "" {
		opts.ListCursorOptions.After = resp.After
		logs, resp, err = c.Organizations.GetAuditLog(ctx, *orgFlag, opts)
		time.Sleep(100 * time.Millisecond)

		if err != nil {
			return as, err
		}

		if len(logs) == 0 {
			break
		}

		log.Printf("%d %q entries returned, now at %s", len(logs), kind, logs[0].GetTimestamp())
		for _, l := range logs {
			as = append(as, l)
			if l.GetTimestamp().Before(since) {
				return as, nil
			}
		}
	}

	return as, nil
}

func webEvents(ctx context.Context, c *github.Client, since time.Time, repos []string, categories map[string]bool, ignoreActions map[string]bool, ignoreUsers map[string]bool) ([]*github.AuditEntry, error) {
	log.Printf("looking for web events impacting %s since %s, watching %v categories, ignoring %v actions and %v users", repos, since, categories, ignoreActions, ignoreUsers)

	matches := []*github.AuditEntry{}
	audit, err := auditLog(ctx, c, "web", since)
	if err != nil {
		return matches, err
	}

	watched := map[string]bool{}
	for _, r := range repos {
		watched[r] = true
	}

	for _, a := range audit {
		category, _, _ := strings.Cut(a.GetAction(), ".")

		if !categories[category] {
			continue
		}

		if ignoreActions[a.GetAction()] {
			continue
		}

		if ignoreUsers[a.GetActor()] {
			continue
		}

		if a.GetAction() == "git.clone" && a.GetRepositoryPublic() {
			continue
		}

		repo := a.GetRepository()
		if repo == "" {
			repo = a.GetRepo()
		}

		log.Printf("repo %s, explanation %s", repo, a.GetExplanation())
		if repo == "" {
			log.Printf("%q is not part of a repository, matching: %s", repo, auditString(a))
			matches = append(matches, a)
			continue
		}

		if len(watched) == 0 {
			log.Printf("no repo filters defined, matching: %s", auditString(a))
			matches = append(matches, a)
			continue
		}
		if watched[repo] {
			log.Printf("%s is being watched, matching: %s", repo, auditString(a))
			matches = append(matches, a)
			continue
		}
	}

	return matches, nil
}

func cloneEvents(ctx context.Context, c *github.Client, since time.Time, ignoreUsers map[string]bool, maxRepos int) ([]*github.AuditEntry, error) {
	log.Printf("looking for clone events impacting private repos since %s, ignoring %v users", since, ignoreUsers)

	matches := []*github.AuditEntry{}
	audit, err := auditLog(ctx, c, "git", since)
	if err != nil {
		return matches, err
	}

	cloneEvents := map[string][]*github.AuditEntry{}

	for _, a := range audit {
		if a.GetAction() != "git.clone" {
			continue
		}

		if ignoreUsers[a.GetActor()] || a.GetRepositoryPublic() {
			continue
		}

		_, ok := cloneEvents[a.GetActor()]
		if !ok {
			cloneEvents[a.GetActor()] = []*github.AuditEntry{}
		}

		cloneEvents[a.GetActor()] = append(cloneEvents[a.GetActor()], a)
	}

	for u, events := range cloneEvents {
		repos := map[string]bool{}
		for _, e := range events {
			repos[e.GetRepository()] = true
		}
		log.Printf("%s has %d git clone events, affected repos: %v", u, len(events), repos)

		if len(repos) >= maxRepos {
			seen := map[string]bool{}
			for _, e := range events {
				if !seen[e.GetRepo()] {
					matches = append(matches, e)
				}
				seen[e.GetRepo()] = true
			}
		}
	}

	return matches, nil
}

func main() {
	flag.Parse()
	ghToken := os.Getenv("GITHUB_TOKEN")
	ctx := context.Background()
	tc := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: ghToken}))
	c := github.NewClient(tc)

	ignoreActions := map[string]bool{}
	for _, a := range strings.Split(*ignoreActionFlag, ",") {
		ignoreActions[a] = true
	}

	ignoreUsers := map[string]bool{}
	for _, a := range strings.Split(*ignoreUsersFlag, ",") {
		ignoreUsers[a] = true
	}

	alertCategories := map[string]bool{}
	for _, a := range strings.Split(*alertCategoriesFlag, ",") {
		alertCategories[a] = true
	}

	cutoff := time.Now().Add(-1 * *webIntervalFlag)
	wes, err := webEvents(ctx, c, cutoff, strings.Split(*reposFlag, ","), alertCategories, ignoreActions, ignoreUsers)
	if err != nil {
		log.Panicf("web events: %v", err)
	}
	for _, e := range wes {
		log.Printf("web event: %s", auditString(e))
	}

	cutoff = time.Now().Add(-1 * *cloneIntervalFlag)
	ces, err := cloneEvents(ctx, c, cutoff, ignoreUsers, *maxReposClonedFlag)
	if err != nil {
		log.Panicf("clone events: %v", err)
	}
	for _, e := range ces {
		log.Printf("excessive clone event: %s", auditString(e))
	}
}
