package introspector

import "github.com/riccivr/bugrouter/internal/resolver"

// TemplateFormat identifies the upstream template syntax.
type TemplateFormat string

const (
	FormatGitHubForm     TemplateFormat = "github-form"
	FormatGitHubMarkdown TemplateFormat = "github-md"
	FormatGitLabMarkdown TemplateFormat = "gitlab-md"
	FormatBugzillaSchema TemplateFormat = "bugzilla-schema"
)

// FieldType defines the input control type in a structured template.
type FieldType string

const (
	FieldTextarea   FieldType = "textarea"
	FieldInput      FieldType = "input"
	FieldDropdown   FieldType = "dropdown"
	FieldCheckboxes FieldType = "checkboxes"
)

// FieldSchema describes a single prompt or input element required by an upstream tracker.
type FieldSchema struct {
	ID          string    `json:"id"`
	Label       string    `json:"label"`
	Description string    `json:"description,omitempty"`
	Type        FieldType `json:"type"`
	Required    bool      `json:"required"`
	Options     []string  `json:"options,omitempty"`
	Value       string    `json:"value,omitempty"` // Pre-filled or default value
}

// MaintainerPolicy records maintainer rules and automated submission constraints.
type MaintainerPolicy struct {
	AIOptOut       bool     `json:"ai_opt_out"`
	OptOutReason   string   `json:"opt_out_reason,omitempty"`
	ChecklistRules []string `json:"checklist_rules,omitempty"`
}

// TemplateSchema represents a discovered upstream issue template or tracker schema.
type TemplateSchema struct {
	Name        string            `json:"name"`
	FileName    string            `json:"file_name,omitempty"`
	Description string            `json:"description,omitempty"`
	TitlePrefix string            `json:"title_prefix,omitempty"`
	Format      TemplateFormat    `json:"format"`
	Protocol    resolver.Protocol `json:"protocol"`
	Labels      []string          `json:"labels,omitempty"`
	Fields      []FieldSchema     `json:"fields,omitempty"`
	RawMarkdown string            `json:"raw_markdown,omitempty"`
	Policy      *MaintainerPolicy `json:"policy,omitempty"`
}
