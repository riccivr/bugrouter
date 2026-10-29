package resolver

import (
	"testing"
)

func TestNormalizeRepoURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "plain https",
			in:   "https://github.com/BurntSushi/ripgrep",
			want: "https://github.com/BurntSushi/ripgrep",
		},
		{
			name: "git suffix",
			in:   "https://github.com/BurntSushi/ripgrep.git",
			want: "https://github.com/BurntSushi/ripgrep",
		},
		{
			name: "git+https prefix with git suffix",
			in:   "git+https://github.com/BurntSushi/ripgrep.git",
			want: "https://github.com/BurntSushi/ripgrep",
		},
		{
			name: "scm:git prefix",
			in:   "scm:git:https://github.com/BurntSushi/ripgrep.git",
			want: "https://github.com/BurntSushi/ripgrep",
		},
		{
			name: "scp style ssh",
			in:   "git@github.com:BurntSushi/ripgrep.git",
			want: "https://github.com/BurntSushi/ripgrep",
		},
		{
			name: "ssh url with git user",
			in:   "ssh://git@github.com/BurntSushi/ripgrep.git",
			want: "https://github.com/BurntSushi/ripgrep",
		},
		{
			name: "git protocol",
			in:   "git://github.com/BurntSushi/ripgrep.git",
			want: "https://github.com/BurntSushi/ripgrep",
		},
		{
			name: "trailing slashes",
			in:   "https://gitlab.com/group/subgroup/project.git///",
			want: "https://gitlab.com/group/subgroup/project",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeRepoURL(tc.in)
			if got != tc.want {
				t.Errorf("NormalizeRepoURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestClassifyTracker(t *testing.T) {
	tests := []struct {
		name        string
		bugsURL     string
		bugsEmail   string
		repoURL     string
		wantProto   Protocol
		wantURL     string
		wantEmail   string
		wantNormRep string
	}{
		{
			name:        "github ssh url",
			repoURL:     "git@github.com:owner/repo.git",
			wantProto:   ProtocolGitHub,
			wantURL:     "https://github.com/owner/repo/issues",
			wantNormRep: "https://github.com/owner/repo",
		},
		{
			name:        "github git+https url",
			repoURL:     "git+https://github.com/owner/repo.git",
			wantProto:   ProtocolGitHub,
			wantURL:     "https://github.com/owner/repo/issues",
			wantNormRep: "https://github.com/owner/repo",
		},
		{
			name:        "gitlab subgroups derived from repo",
			repoURL:     "https://gitlab.com/group/subgroup/project",
			wantProto:   ProtocolGitLab,
			wantURL:     "https://gitlab.com/group/subgroup/project/issues",
			wantNormRep: "https://gitlab.com/group/subgroup/project",
		},
		{
			name:        "gitlab explicit issues url",
			bugsURL:     "https://gitlab.com/group/subgroup/project/-/issues",
			repoURL:     "https://gitlab.com/group/subgroup/project.git",
			wantProto:   ProtocolGitLab,
			wantURL:     "https://gitlab.com/group/subgroup/project/-/issues",
			wantNormRep: "https://gitlab.com/group/subgroup/project",
		},
		{
			name:        "codeberg repository",
			repoURL:     "https://codeberg.org/forgejo/forgejo",
			wantProto:   ProtocolCodeberg,
			wantURL:     "https://codeberg.org/forgejo/forgejo/issues",
			wantNormRep: "https://codeberg.org/forgejo/forgejo",
		},
		{
			name:        "blender gitea forge",
			repoURL:     "https://projects.blender.org/blender/blender",
			wantProto:   ProtocolGitea,
			wantURL:     "https://projects.blender.org/blender/blender/issues",
			wantNormRep: "https://projects.blender.org/blender/blender",
		},
		{
			name:        "gitea.com repository",
			repoURL:     "https://gitea.com/gitea/tea",
			wantProto:   ProtocolGitea,
			wantURL:     "https://gitea.com/gitea/tea/issues",
			wantNormRep: "https://gitea.com/gitea/tea",
		},
		{
			name:        "forgejo custom instance",
			repoURL:     "https://forgejo.example.org/infra/tools",
			wantProto:   ProtocolGitea,
			wantURL:     "https://forgejo.example.org/infra/tools/issues",
			wantNormRep: "https://forgejo.example.org/infra/tools",
		},
		{
			name:      "bugzilla cgi url",
			bugsURL:   "https://bugzilla.mozilla.org/enter_bug.cgi",
			wantProto: ProtocolBugzilla,
			wantURL:   "https://bugzilla.mozilla.org/enter_bug.cgi",
		},
		{
			name:      "gnu coreutils email",
			bugsEmail: "bug-coreutils@gnu.org",
			wantProto: ProtocolDebbugs,
			wantEmail: "bug-coreutils@gnu.org",
		},
		{
			name:      "gnu coreutils mailto bugs url",
			bugsURL:   "mailto:bug-coreutils@gnu.org",
			wantProto: ProtocolDebbugs,
			wantEmail: "bug-coreutils@gnu.org",
		},
		{
			name:      "debian debbugs url",
			bugsURL:   "https://bugs.debian.org/cgi-bin/pkgreport.cgi?pkg=curl",
			wantProto: ProtocolDebbugs,
			wantURL:   "https://bugs.debian.org/cgi-bin/pkgreport.cgi?pkg=curl",
		},
		{
			name:      "sourcehut repository",
			bugsURL:   "https://todo.sr.ht/~emersion/gammastep",
			wantProto: ProtocolSourceHut,
			wantURL:   "https://todo.sr.ht/~emersion/gammastep",
		},
		{
			name:        "spoofed github url in query parameter",
			bugsURL:     "https://evil.com/redirect?url=https://github.com/owner/repo",
			wantProto:   ProtocolWebURL,
			wantURL:     "https://evil.com/redirect?url=https://github.com/owner/repo",
			wantNormRep: "",
		},
		{
			name:        "jira atlassian net url",
			bugsURL:     "https://myteam.atlassian.net/browse/PROJ-123",
			wantProto:   ProtocolJira,
			wantURL:     "https://myteam.atlassian.net/browse/PROJ-123",
			wantNormRep: "",
		},
		{
			name:        "jira custom host with rest api",
			bugsURL:     "https://jira.corp.internal/rest/api/2/issue",
			wantProto:   ProtocolJira,
			wantURL:     "https://jira.corp.internal/rest/api/2/issue",
			wantNormRep: "",
		},
		{
			name:        "linear app url",
			bugsURL:     "https://linear.app/myteam/issue/ENG-101",
			wantProto:   ProtocolLinear,
			wantURL:     "https://linear.app/myteam/issue/ENG-101",
			wantNormRep: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tracker, normRepo := ClassifyTracker(tc.bugsURL, tc.bugsEmail, tc.repoURL)
			if tracker.Protocol != tc.wantProto {
				t.Errorf("Protocol = %q, want %q", tracker.Protocol, tc.wantProto)
			}
			if tracker.URL != tc.wantURL {
				t.Errorf("URL = %q, want %q", tracker.URL, tc.wantURL)
			}
			if tracker.Email != tc.wantEmail {
				t.Errorf("Email = %q, want %q", tracker.Email, tc.wantEmail)
			}
			if tc.wantNormRep != "" && normRepo != tc.wantNormRep {
				t.Errorf("normalizedRepo = %q, want %q", normRepo, tc.wantNormRep)
			}
		})
	}
}
