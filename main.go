// github-audit-alerter alerts on audit events
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/google/go-github/v51/github"
	"github.com/slack-go/slack"
)

var (
	// globalActionsIgnore are regexps for actions to ignore globally
	globalActionsIgnore = []string{
		"issue.*",
		"org_credential_authorization.*",
		"org.self_hosted_runner_.*",
		"environment.create",
		"repo.create",
		"org.sso_response",
		"repository_secret_scanning.enable",
		"repository_projects.*",
		"packages.package_version_published",
		"required_status_check.create",
		"protected_branch.authorized_users_teams",
		"repository_dependency_graph.enable",
		"personal_access_token.request_created",
		"repository_vulnerability_alerts.enable",
		"public_key.update",
		"project.*",
		"integration_installation.repositories_removed",
		"account.plan_change",
		"pull_request.*",
		"repo.remove_member",
		"environment.add_protection_rule",
		"repo.pages_.*",
		"repository_vulnerability_alert.dismiss",
		"repository_vulnerability_alert.resolve",
		"team.add_repository",
		"workflows.*",
	}

	// nonCriticalActionsIgnore are regexps for actions to ignore for non-critical repos
	nonCriticalActionsIgnore = []string{
		"protected_branch.*",
		"environment.update_protection_rule",
		"protected_branch.update_allow_force_pushes_enforcement_level",
		"repo.change_merge_setting",
		"private_repository_forking.*",
		"org.add_outside_collaborator",
		"repository_invitation.accept",
		"integration_installation.*",
		"repo.add_member",
		"repo.rename",
		"repo.archived",
		"team.*",
		"repo.destroy",
		"repository_vulnerability_alert.create",
		"integration_installation.repositories_added",
	}
)

var (
	intervalFlag       = flag.Duration("interval", 15*time.Minute, "How far to go backwards searching for actions to alert on")
	maxReposClonedFlag = flag.Int("max-repos-cloned-per-user", 3, "maximum repositories before creating a user alert")
	cloneIntervalFlag  = flag.Duration("clone-search-interval", 24*time.Hour, "How far to go backwards searching for git clone events")
	criticalReposFlag  = flag.String("critical-repos", "", "critical repositories for more stringent checking, comma separated")
	orgFlag            = flag.String("org", "", "Github Organization to query")
)

func auditString(a *github.AuditEntry) string {
	b, _ := json.Marshal(a)
	return string(b)
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

	for _, l := range logs {
		as = append(as, l)
		if l.GetTimestamp().Before(since) {
			return as, nil
		}
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

		for _, l := range logs {
			as = append(as, l)
			if l.GetTimestamp().Before(since) {
				return as, nil
			}
		}

		if len(as)%1000 == 0 {
			log.Printf("%d %q entries returned, now at %s", len(as), kind, logs[0].GetTimestamp())
		}
	}

	return as, nil
}

type Settings struct {
	Since          time.Time
	MaxClonesSince time.Time
	Org            string

	GlobalIgnoreActions      []string
	NonCriticalIgnoreActions []string
	CriticalRepos            []string

	MaxClonedRepos int
}

func webEvents(ctx context.Context, c *github.Client, s Settings) ([]*github.AuditEntry, error) {
	log.Printf("looking for web events impacting %s since %s", s.Org, s.Since)

	ig := []string{}
	for _, i := range s.GlobalIgnoreActions {
		ig = append(ig, fmt.Sprintf("^%s$", i))
	}
	globalIgnoreRe := regexp.MustCompile(strings.Join(ig, "|"))

	ig = []string{}
	for _, i := range s.NonCriticalIgnoreActions {
		ig = append(ig, fmt.Sprintf("^%s$", i))
	}
	nonCriticalIgnoreRe := regexp.MustCompile(strings.Join(ig, "|"))

	matches := []*github.AuditEntry{}
	audit, err := auditLog(ctx, c, "web", s.Since)
	if err != nil {
		return matches, err
	}

	critical := map[string]bool{}
	for _, r := range s.CriticalRepos {
		if strings.Contains(r, "/") {
			critical[r] = true
			continue
		}
		critical[fmt.Sprintf("%s/%s", s.Org, r)] = true
	}

	for _, a := range audit {
		if globalIgnoreRe.MatchString(a.GetAction()) {
			continue
		}
		if !critical[a.GetRepo()] && nonCriticalIgnoreRe.MatchString(a.GetAction()) {
			continue
		}

		if isBot(a.GetActor()) {
			continue
		}

		log.Printf("found: %s", auditString(a))
		matches = append(matches, a)
	}

	return matches, nil
}

func isBot(s string) bool {
	if strings.HasSuffix(s, "-bot") {
		return true
	}
	if strings.HasSuffix(s, "[bot]") {
		return true
	}
	if strings.HasPrefix(s, "deploy") {
		return true
	}
	if strings.HasSuffix(s, "guardian") {
		return true
	}
	return false
}

func cloneEvents(ctx context.Context, c *github.Client, s Settings) ([]*github.AuditEntry, error) {
	log.Printf("looking for clone events impacting private repos since %s", s.MaxClonesSince)

	matches := []*github.AuditEntry{}
	audit, err := auditLog(ctx, c, "git", s.MaxClonesSince)
	if err != nil {
		return matches, err
	}

	cloneEvents := map[string][]*github.AuditEntry{}

	for _, a := range audit {
		if a.GetAction() != "git.clone" {
			continue
		}

		if a.GetRepositoryPublic() {
			continue
		}

		if isBot(a.GetActor()) {
			continue
		}

		_, ok := cloneEvents[a.GetActor()]
		if !ok {
			cloneEvents[a.GetActor()] = []*github.AuditEntry{}
		}

		cloneEvents[a.GetActor()] = append(cloneEvents[a.GetActor()], a)
	}

	log.Printf("finding excessive clones after %s", s.Since)
	for u, events := range cloneEvents {
		repos := map[string]bool{}
		for _, e := range events {
			repos[e.GetRepository()] = true
		}

		log.Printf("%s has %d git clone events, affected repos: %v", u, len(events), repos)

		if len(repos) >= s.MaxClonedRepos {
			seen := map[string]bool{}
			for _, e := range events {
				if e.GetTimestamp().Before(s.Since) {
					log.Printf("ignoring excessive clone before %s: %s", s.Since, auditString(e))
					continue
				}
				if !seen[e.GetRepo()] {
					matches = append(matches, e)
					log.Printf("found: %s", auditString(e))
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

	if ghToken == "" {
		log.Fatalf("GITHUB_TOKEN must be set")
	}

	if *orgFlag == "" {
		log.Fatalf("--org must be passed")
	}

	ctx := context.Background()
	tc := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: ghToken}))
	c := github.NewClient(tc)

	s := Settings{
		Org:                      *orgFlag,
		Since:                    time.Now().Add(-1 * *intervalFlag),
		GlobalIgnoreActions:      globalActionsIgnore,
		NonCriticalIgnoreActions: nonCriticalActionsIgnore,
		MaxClonedRepos:           *maxReposClonedFlag,
		MaxClonesSince:           time.Now().Add(-1 * *cloneIntervalFlag),
		CriticalRepos:            strings.Split(*criticalReposFlag, ","),
	}

	wes, err := webEvents(ctx, c, s)
	if err != nil {
		log.Panicf("web events: %v", err)
	}
	postFailures := 0
	webhook := os.Getenv("GH_AUDIT_SLACK_WEBHOOK")

	for _, e := range wes {
		if err := notify(webhook, auditMsg(e)); err != nil {
			postFailures++
			log.Printf("notify failed: %v", err)
		}
	}

	ces, err := cloneEvents(ctx, c, s)
	if err != nil {
		log.Panicf("clone events: %v", err)
	}
	for _, e := range ces {
		if err := notify(webhook, fmt.Sprintf("excessive clone[>=%d]: %s", s.MaxClonedRepos, auditMsg(e))); err != nil {
			postFailures++
			log.Printf("notify failed: %v", err)
		}
	}

	if postFailures > 0 {
		log.Panicf("%d post failures: %v", postFailures, err)
	}
}

func auditMsg(a *github.AuditEntry) string {
	var sb strings.Builder
	repo := a.GetRepo()
	if repo == "" {
		repo = a.GetRepository()
	}

	location := a.GetOrg()
	if repo != "" {
		if strings.Contains(repo, "/") {
			location = repo
		} else {
			location = fmt.Sprintf("%s/%s", a.GetOrg(), repo)
		}
	}

	sb.WriteString(fmt.Sprintf("%s: *%s* on *%s*", a.GetActor(), a.GetAction(), location))

	if a.GetPreviousVisibility() != "" {
		sb.WriteString(fmt.Sprintf("visibility: %s->%s", a.GetPreviousVisibility(), a.GetVisibility()))
	}

	if a.GetName() != "" {
		sb.WriteString(fmt.Sprintf(" name: %q", a.GetName()))
	}

	if a.GetExplanation() != "" {
		sb.WriteString(fmt.Sprintf(" explanation: %q", a.GetExplanation()))
	}

	ts := a.GetCreatedAt()
	if ts.IsZero() {
		ts = a.GetTimestamp()
	}

	sb.WriteString(fmt.Sprintf(": %s", ts))

	u := url.URL{
		Scheme: "https",
		Host:   "github.com",
		Path:   fmt.Sprintf("/organizations/%s/settings/audit-log", a.GetOrg()),
	}
	q := u.Query()
	q.Set("q", fmt.Sprintf("action:%s actor:%s", a.GetAction(), a.GetActor()))
	u.RawQuery = q.Encode()

	sb.WriteString(fmt.Sprintf(" [<%s|logs>]", u.String()))
	return sb.String()
}

func notify(url string, text string) error {
	if url == "" {
		log.Printf("[would notify] %s", text)
		return nil
	}

	log.Printf("[webhook post] %s", text)
	return slack.PostWebhook(url, &slack.WebhookMessage{
		Text: text,
	})
}
