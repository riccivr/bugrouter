package introspector

import (
	"reflect"
	"testing"

	"github.com/riccivr/bugrouter/internal/resolver"
)

func TestParseGitHubYAMLForm(t *testing.T) {
	yamlData := `
name: "Bug Report"
description: "File a bug report against the compiler"
title: "[BUG]: "
labels: ["bug", "triage"]
body:
  - type: markdown
    attributes:
      value: "Thanks for taking the time to report!"
  - type: textarea
    id: what-happened
    attributes:
      label: "What happened?"
      description: "Describe the bug you encountered"
      value: "Observed crash"
    validations:
      required: true
  - type: input
    id: version
    attributes:
      label: "Version"
      description: "What version are you using?"
    validations:
      required: false
  - type: dropdown
    id: os
    attributes:
      label: "Operating System"
      options:
        - "Linux"
        - "macOS"
        - "Windows"
    validations:
      required: true
  - type: checkboxes
    id: terms
    attributes:
      label: "Agreements"
      options:
        - label: "I have read the code of conduct"
          required: true
        - label: "I am using the latest version"
`

	schema, err := ParseGitHubYAMLForm("bug_report.yml", []byte(yamlData))
	if err != nil {
		t.Fatalf("ParseGitHubYAMLForm failed: %v", err)
	}

	if schema.Name != "Bug Report" {
		t.Errorf("Name = %q, want %q", schema.Name, "Bug Report")
	}
	if schema.Description != "File a bug report against the compiler" {
		t.Errorf("Description = %q", schema.Description)
	}
	if schema.TitlePrefix != "[BUG]: " {
		t.Errorf("TitlePrefix = %q, want [BUG]: ", schema.TitlePrefix)
	}
	expectedLabels := []string{"bug", "triage"}
	if !reflect.DeepEqual(schema.Labels, expectedLabels) {
		t.Errorf("Labels = %v, want %v", schema.Labels, expectedLabels)
	}
	if schema.Format != FormatGitHubForm {
		t.Errorf("Format = %v, want %v", schema.Format, FormatGitHubForm)
	}
	if schema.Protocol != resolver.ProtocolGitHub {
		t.Errorf("Protocol = %v, want %v", schema.Protocol, resolver.ProtocolGitHub)
	}

	// Should have 4 fields (markdown block skipped)
	if len(schema.Fields) != 4 {
		t.Fatalf("Fields count = %d, want 4", len(schema.Fields))
	}

	// 1. Textarea
	f0 := schema.Fields[0]
	if f0.ID != "what-happened" || f0.Type != FieldTextarea || !f0.Required || f0.Value != "Observed crash" {
		t.Errorf("Field 0 unexpected: %+v", f0)
	}

	// 2. Input
	f1 := schema.Fields[1]
	if f1.ID != "version" || f1.Type != FieldInput || f1.Required {
		t.Errorf("Field 1 unexpected: %+v", f1)
	}

	// 3. Dropdown
	f2 := schema.Fields[2]
	if f2.ID != "os" || f2.Type != FieldDropdown || !f2.Required {
		t.Errorf("Field 2 unexpected: %+v", f2)
	}
	expectedOptions := []string{"Linux", "macOS", "Windows"}
	if !reflect.DeepEqual(f2.Options, expectedOptions) {
		t.Errorf("Dropdown options = %v, want %v", f2.Options, expectedOptions)
	}

	// 4. Checkboxes
	f3 := schema.Fields[3]
	if f3.ID != "terms" || f3.Type != FieldCheckboxes {
		t.Errorf("Field 3 unexpected: %+v", f3)
	}
	expectedCheckOptions := []string{"I have read the code of conduct", "I am using the latest version"}
	if !reflect.DeepEqual(f3.Options, expectedCheckOptions) {
		t.Errorf("Checkboxes options = %v, want %v", f3.Options, expectedCheckOptions)
	}

	// Test multiline labels
	multilineLabelsYAML := `
name: Multiline
labels:
  - bug
  - backend
body:
  - type: input
    id: title
    attributes:
      label: Summary
`
	schema2, err := ParseGitHubYAMLForm("multi.yml", []byte(multilineLabelsYAML))
	if err != nil {
		t.Fatalf("ParseGitHubYAMLForm multiline failed: %v", err)
	}
	expectedLabels2 := []string{"bug", "backend"}
	if !reflect.DeepEqual(schema2.Labels, expectedLabels2) {
		t.Errorf("schema2.Labels = %v, want %v", schema2.Labels, expectedLabels2)
	}
}

func TestParseMarkdownTemplate(t *testing.T) {
	tests := []struct {
		name         string
		protocol     resolver.Protocol
		input        string
		wantFormat   TemplateFormat
		wantName     string
		wantDesc     string
		wantPrefix   string
		wantLabels   []string
		wantFieldLen int
	}{
		{
			name:     "github markdown with frontmatter",
			protocol: resolver.ProtocolGitHub,
			input: `---
name: Bug Report
about: Create a bug report
title: "[BUG] "
labels: bug, needs-triage
---

## Description
A clear description of what the bug is.

## Steps to Reproduce
1. Go to '...'
2. Click on '....'

### Additional Context
Add any other context.
`,
			wantFormat:   FormatGitHubMarkdown,
			wantName:     "Bug Report",
			wantDesc:     "Create a bug report",
			wantPrefix:   "[BUG] ",
			wantLabels:   []string{"bug", "needs-triage"},
			wantFieldLen: 3,
		},
		{
			name:     "gitlab markdown without frontmatter",
			protocol: resolver.ProtocolGitLab,
			input: `## Summary
Summarize the bug.

## Steps to reproduce
How to trigger.

### What is the expected correct behavior?
What should happen.
`,
			wantFormat:   FormatGitLabMarkdown,
			wantName:     "default",
			wantDesc:     "",
			wantPrefix:   "",
			wantLabels:   nil,
			wantFieldLen: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			schema, err := ParseMarkdownTemplate(tc.wantName+".md", tc.protocol, []byte(tc.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if schema.Format != tc.wantFormat {
				t.Errorf("Format = %v, want %v", schema.Format, tc.wantFormat)
			}
			if schema.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", schema.Name, tc.wantName)
			}
			if schema.Description != tc.wantDesc {
				t.Errorf("Description = %q, want %q", schema.Description, tc.wantDesc)
			}
			if schema.TitlePrefix != tc.wantPrefix {
				t.Errorf("TitlePrefix = %q, want %q", schema.TitlePrefix, tc.wantPrefix)
			}
			if tc.wantLabels != nil && !reflect.DeepEqual(schema.Labels, tc.wantLabels) {
				t.Errorf("Labels = %v, want %v", schema.Labels, tc.wantLabels)
			}
			if len(schema.Fields) != tc.wantFieldLen {
				t.Fatalf("Fields len = %d, want %d", len(schema.Fields), tc.wantFieldLen)
			}
			for _, f := range schema.Fields {
				if f.Type != FieldTextarea {
					t.Errorf("Field %s type = %v, want %v", f.ID, f.Type, FieldTextarea)
				}
				if f.ID == "" {
					t.Errorf("Field label %q has empty normalized ID", f.Label)
				}
			}
		})
	}
}

func TestParseBugzillaRESTSchema(t *testing.T) {
	productJSON := `{
		"products": [
			{
				"name": "Firefox",
				"description": "Mozilla Firefox Web Browser",
				"components": [
					{"name": "General"},
					{"name": "Developer Tools"}
				],
				"versions": [
					{"name": "unspecified"},
					{"name": "120.0"}
				]
			}
		]
	}`

	schema, err := ParseBugzillaRESTSchema([]byte(productJSON))
	if err != nil {
		t.Fatalf("ParseBugzillaRESTSchema failed: %v", err)
	}

	if schema.Format != FormatBugzillaSchema {
		t.Errorf("Format = %v, want %v", schema.Format, FormatBugzillaSchema)
	}
	if schema.Protocol != resolver.ProtocolBugzilla {
		t.Errorf("Protocol = %v, want %v", schema.Protocol, resolver.ProtocolBugzilla)
	}
	if len(schema.Fields) != 4 {
		t.Fatalf("Fields len = %d, want 4", len(schema.Fields))
	}

	// Verify product field
	fProd := schema.Fields[0]
	if fProd.ID != "product" || fProd.Type != FieldDropdown || !fProd.Required || fProd.Value != "Firefox" {
		t.Errorf("Product field unexpected: %+v", fProd)
	}

	// Verify component field
	fComp := schema.Fields[1]
	if fComp.ID != "component" || fComp.Type != FieldDropdown || !fComp.Required || fComp.Value != "General" {
		t.Errorf("Component field unexpected: %+v", fComp)
	}

	// Verify version field
	fVer := schema.Fields[2]
	if fVer.ID != "version" || fVer.Type != FieldDropdown || fVer.Value != "unspecified" {
		t.Errorf("Version field unexpected: %+v", fVer)
	}

	// Verify severity field
	fSev := schema.Fields[3]
	if fSev.ID != "severity" || fSev.Type != FieldDropdown || fSev.Value != "normal" {
		t.Errorf("Severity field unexpected: %+v", fSev)
	}
}

func TestParseGitHubYAMLFormWithTopLevelAssignees(t *testing.T) {
	yamlData := `
name: "Bug Report"
description: "File a bug"
body:
  - type: dropdown
    id: os
    attributes:
      label: Operating System
      options:
        - Linux
        - macOS
assignees:
  - octocat
  - maintainer
`
	schema, err := ParseGitHubYAMLForm("bug_report.yml", []byte(yamlData))
	if err != nil {
		t.Fatalf("ParseGitHubYAMLForm failed: %v", err)
	}
	if len(schema.Fields) != 1 {
		t.Fatalf("expected 1 field, got %d", len(schema.Fields))
	}
	field := schema.Fields[0]
	if field.ID != "os" {
		t.Errorf("field ID = %q, want os", field.ID)
	}
	expectedOptions := []string{"Linux", "macOS"}
	if !reflect.DeepEqual(field.Options, expectedOptions) {
		t.Errorf("field Options = %v, want %v (top-level assignees polluted field options)", field.Options, expectedOptions)
	}
}

func TestParseBugzillaRESTSchemaEmpty(t *testing.T) {
	emptyJSONs := [][]byte{
		[]byte(`{}`),
		[]byte(`{"products": []}`),
		[]byte(`{"fields": []}`),
		[]byte(`{"error": "not found"}`),
	}

	for _, data := range emptyJSONs {
		schema, err := ParseBugzillaRESTSchema(data)
		if err != ErrNoTemplateFound {
			t.Errorf("ParseBugzillaRESTSchema(%s) err = %v, want ErrNoTemplateFound (got schema: %+v)", string(data), err, schema)
		}
	}
}
