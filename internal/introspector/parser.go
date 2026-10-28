package introspector

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/riccivr/bugrouter/internal/resolver"
)

func stripQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func parseInlineList(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		item := stripQuotes(p)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

func stripInlineComment(line string) string {
	inSingle := false
	inDouble := false
	for i, r := range line {
		if r == '\'' && !inDouble {
			inSingle = !inSingle
		} else if r == '"' && !inSingle {
			inDouble = !inDouble
		} else if r == '#' && !inSingle && !inDouble {
			return strings.TrimRight(line[:i], " \t")
		}
	}
	return line
}

func normalizeHeadingID(text string) string {
	text = strings.ToLower(text)
	var sb strings.Builder
	for _, r := range text {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('_')
		}
	}
	raw := sb.String()
	for strings.Contains(raw, "__") {
		raw = strings.ReplaceAll(raw, "__", "_")
	}
	return strings.Trim(raw, "_")
}

// ParseGitHubYAMLForm parses GitHub issue form definitions into a TemplateSchema.
func ParseGitHubYAMLForm(fileName string, data []byte) (*TemplateSchema, error) {
	schema := &TemplateSchema{
		FileName: fileName,
		Format:   FormatGitHubForm,
		Protocol: resolver.ProtocolGitHub,
	}

	lines := strings.Split(string(data), "\n")
	inBody := false
	inLabels := false
	inOptions := false
	currentSection := ""

	var currentField *FieldSchema
	isMarkdown := false

	flushField := func() {
		if currentField != nil && !isMarkdown {
			schema.Fields = append(schema.Fields, *currentField)
		}
		currentField = nil
		isMarkdown = false
		currentSection = ""
		inOptions = false
	}

	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, "\r\n")
		line = stripInlineComment(line)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if !inBody {
			if strings.HasPrefix(trimmed, "body:") {
				inBody = true
				inLabels = false
				continue
			}
			if strings.HasPrefix(trimmed, "name:") {
				schema.Name = stripQuotes(strings.TrimPrefix(trimmed, "name:"))
				inLabels = false
				continue
			}
			if strings.HasPrefix(trimmed, "description:") {
				schema.Description = stripQuotes(strings.TrimPrefix(trimmed, "description:"))
				inLabels = false
				continue
			}
			if strings.HasPrefix(trimmed, "title:") {
				schema.TitlePrefix = stripQuotes(strings.TrimPrefix(trimmed, "title:"))
				inLabels = false
				continue
			}
			if strings.HasPrefix(trimmed, "labels:") {
				rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "labels:"))
				if strings.HasPrefix(rest, "[") {
					schema.Labels = parseInlineList(rest)
					inLabels = false
				} else if rest != "" {
					schema.Labels = append(schema.Labels, stripQuotes(rest))
					inLabels = false
				} else {
					inLabels = true
				}
				continue
			}
			if inLabels && strings.HasPrefix(trimmed, "-") {
				val := stripQuotes(strings.TrimSpace(strings.TrimPrefix(trimmed, "-")))
				if val != "" {
					schema.Labels = append(schema.Labels, val)
				}
				continue
			}
			continue
		}

		// Inside body
		if strings.HasPrefix(trimmed, "- type:") || trimmed == "-" {
			flushField()
			currentField = &FieldSchema{}
			if strings.HasPrefix(trimmed, "- type:") {
				typeVal := stripQuotes(strings.TrimPrefix(trimmed, "- type:"))
				if typeVal == "markdown" {
					isMarkdown = true
				}
				currentField.Type = FieldType(typeVal)
			}
			continue
		}

		if currentField == nil {
			continue
		}

		if strings.HasPrefix(trimmed, "type:") {
			typeVal := stripQuotes(strings.TrimPrefix(trimmed, "type:"))
			if typeVal == "markdown" {
				isMarkdown = true
			}
			currentField.Type = FieldType(typeVal)
			continue
		}

		if strings.HasPrefix(trimmed, "id:") {
			currentField.ID = stripQuotes(strings.TrimPrefix(trimmed, "id:"))
			continue
		}

		if strings.HasPrefix(trimmed, "attributes:") {
			currentSection = "attributes"
			inOptions = false
			continue
		}

		if strings.HasPrefix(trimmed, "validations:") {
			currentSection = "validations"
			inOptions = false
			continue
		}

		if currentSection == "attributes" {
			if strings.HasPrefix(trimmed, "options:") {
				rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "options:"))
				if strings.HasPrefix(rest, "[") {
					currentField.Options = parseInlineList(rest)
					inOptions = false
				} else {
					inOptions = true
				}
				continue
			}

			if inOptions && strings.HasPrefix(trimmed, "-") {
				optStr := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
				if strings.HasPrefix(optStr, "label:") {
					optStr = strings.TrimSpace(strings.TrimPrefix(optStr, "label:"))
				}
				optStr = stripQuotes(optStr)
				if optStr != "" {
					currentField.Options = append(currentField.Options, optStr)
				}
				continue
			}

			if strings.HasPrefix(trimmed, "label:") {
				inOptions = false
				currentField.Label = stripQuotes(strings.TrimPrefix(trimmed, "label:"))
				continue
			}
			if strings.HasPrefix(trimmed, "description:") {
				inOptions = false
				currentField.Description = stripQuotes(strings.TrimPrefix(trimmed, "description:"))
				continue
			}
			if strings.HasPrefix(trimmed, "value:") {
				inOptions = false
				currentField.Value = stripQuotes(strings.TrimPrefix(trimmed, "value:"))
				continue
			}
		}

		if currentSection == "validations" {
			if strings.HasPrefix(trimmed, "required:") {
				reqVal := strings.ToLower(stripQuotes(strings.TrimPrefix(trimmed, "required:")))
				currentField.Required = (reqVal == "true" || reqVal == "yes" || reqVal == "1")
				continue
			}
		}
	}

	flushField()
	return schema, nil
}

// ParseMarkdownTemplate parses Markdown issue templates with optional YAML frontmatter.
func ParseMarkdownTemplate(fileName string, protocol resolver.Protocol, data []byte) (*TemplateSchema, error) {
	format := FormatGitHubMarkdown
	if protocol == resolver.ProtocolGitLab {
		format = FormatGitLabMarkdown
	}

	schema := &TemplateSchema{
		FileName: fileName,
		Format:   format,
		Protocol: protocol,
	}

	lines := strings.Split(string(data), "\n")
	var frontmatterLines []string
	var bodyLines []string

	inFrontmatter := false
	frontmatterDone := false

	for i, rawLine := range lines {
		line := strings.TrimRight(rawLine, "\r\n")
		trimmed := strings.TrimSpace(line)

		if i == 0 && trimmed == "---" {
			inFrontmatter = true
			continue
		}

		if inFrontmatter {
			if trimmed == "---" {
				inFrontmatter = false
				frontmatterDone = true
				continue
			}
			frontmatterLines = append(frontmatterLines, line)
			continue
		}

		bodyLines = append(bodyLines, line)
	}

	if inFrontmatter && !frontmatterDone {
		bodyLines = append(frontmatterLines, bodyLines...)
		frontmatterLines = nil
	}

	inLabels := false
	for _, line := range frontmatterLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.HasPrefix(trimmed, "name:") {
			schema.Name = stripQuotes(strings.TrimPrefix(trimmed, "name:"))
			inLabels = false
			continue
		}
		if strings.HasPrefix(trimmed, "about:") {
			schema.Description = stripQuotes(strings.TrimPrefix(trimmed, "about:"))
			inLabels = false
			continue
		}
		if strings.HasPrefix(trimmed, "description:") {
			schema.Description = stripQuotes(strings.TrimPrefix(trimmed, "description:"))
			inLabels = false
			continue
		}
		if strings.HasPrefix(trimmed, "title:") {
			schema.TitlePrefix = stripQuotes(strings.TrimPrefix(trimmed, "title:"))
			inLabels = false
			continue
		}
		if strings.HasPrefix(trimmed, "labels:") {
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "labels:"))
			if strings.HasPrefix(rest, "[") {
				schema.Labels = parseInlineList(rest)
				inLabels = false
			} else if strings.Contains(rest, ",") {
				parts := strings.Split(rest, ",")
				for _, p := range parts {
					item := stripQuotes(p)
					if item != "" {
						schema.Labels = append(schema.Labels, item)
					}
				}
				inLabels = false
			} else if rest != "" {
				schema.Labels = append(schema.Labels, stripQuotes(rest))
				inLabels = false
			} else {
				inLabels = true
			}
			continue
		}
		if inLabels && strings.HasPrefix(trimmed, "-") {
			val := stripQuotes(strings.TrimSpace(strings.TrimPrefix(trimmed, "-")))
			if val != "" {
				schema.Labels = append(schema.Labels, val)
			}
			continue
		}
	}

	bodyText := strings.TrimSpace(strings.Join(bodyLines, "\n"))
	schema.RawMarkdown = bodyText

	for _, line := range bodyLines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "## ") || strings.HasPrefix(trimmed, "### ") {
			heading := strings.TrimSpace(strings.TrimLeft(trimmed, "#"))
			id := normalizeHeadingID(heading)
			if id != "" {
				schema.Fields = append(schema.Fields, FieldSchema{
					ID:       id,
					Label:    heading,
					Type:     FieldTextarea,
					Required: false,
				})
			}
		}
	}

	if schema.Name == "" {
		schema.Name = strings.TrimSuffix(fileName, ".md")
	}

	return schema, nil
}

// ParseBugzillaRESTSchema parses product and field definitions into a TemplateSchema.
func ParseBugzillaRESTSchema(data []byte) (*TemplateSchema, error) {
	var prodPayload struct {
		Products []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Components  []struct {
				Name string `json:"name"`
			} `json:"components"`
			Versions []struct {
				Name string `json:"name"`
			} `json:"versions"`
		} `json:"products"`
	}

	var fieldPayload struct {
		Fields []struct {
			Name   string `json:"name"`
			Values []struct {
				Name string `json:"name"`
			} `json:"values"`
		} `json:"fields"`
	}

	prodErr := json.Unmarshal(data, &prodPayload)
	fieldErr := json.Unmarshal(data, &fieldPayload)
	if prodErr != nil && fieldErr != nil {
		return nil, fmt.Errorf("parse bugzilla rest schema: %w", prodErr)
	}

	var productOptions []string
	var componentOptions []string
	var versionOptions []string
	var severityOptions []string

	if len(prodPayload.Products) > 0 {
		compSeen := make(map[string]bool)
		verSeen := make(map[string]bool)
		for _, p := range prodPayload.Products {
			if p.Name != "" {
				productOptions = append(productOptions, p.Name)
			}
			for _, c := range p.Components {
				if c.Name != "" && !compSeen[c.Name] {
					compSeen[c.Name] = true
					componentOptions = append(componentOptions, c.Name)
				}
			}
			for _, v := range p.Versions {
				if v.Name != "" && !verSeen[v.Name] {
					verSeen[v.Name] = true
					versionOptions = append(versionOptions, v.Name)
				}
			}
		}
	}

	if len(fieldPayload.Fields) > 0 {
		for _, f := range fieldPayload.Fields {
			name := strings.ToLower(f.Name)
			var vals []string
			for _, v := range f.Values {
				if v.Name != "" {
					vals = append(vals, v.Name)
				}
			}
			switch name {
			case "product":
				productOptions = append(productOptions, vals...)
			case "component":
				componentOptions = append(componentOptions, vals...)
			case "version":
				versionOptions = append(versionOptions, vals...)
			case "bug_severity", "severity":
				severityOptions = append(severityOptions, vals...)
			}
		}
	}

	if len(severityOptions) == 0 {
		severityOptions = []string{"blocker", "critical", "major", "normal", "minor", "trivial"}
	}

	fields := []FieldSchema{
		{
			ID:       "product",
			Label:    "Product",
			Type:     FieldDropdown,
			Required: true,
			Options:  productOptions,
		},
		{
			ID:       "component",
			Label:    "Component",
			Type:     FieldDropdown,
			Required: true,
			Options:  componentOptions,
		},
		{
			ID:       "version",
			Label:    "Version",
			Type:     FieldDropdown,
			Required: false,
			Options:  versionOptions,
		},
		{
			ID:       "severity",
			Label:    "Severity",
			Type:     FieldDropdown,
			Required: false,
			Options:  severityOptions,
			Value:    "normal",
		},
	}

	if len(productOptions) > 0 {
		fields[0].Value = productOptions[0]
	}
	if len(componentOptions) > 0 {
		fields[1].Value = componentOptions[0]
	}
	if len(versionOptions) > 0 {
		fields[2].Value = versionOptions[0]
	}

	return &TemplateSchema{
		Name:     "Bugzilla Bug Schema",
		Format:   FormatBugzillaSchema,
		Protocol: resolver.ProtocolBugzilla,
		Fields:   fields,
	}, nil
}
