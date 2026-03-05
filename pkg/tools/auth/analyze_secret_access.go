// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

var (
	policyPathBlockRe = regexp.MustCompile(`(?s)path\s+"([^"]+)"\s*\{(.*?)\}`)
	capabilitiesRe    = regexp.MustCompile(`capabilities\s*=\s*\[(.*?)\]`)
	legacyPolicyRe    = regexp.MustCompile(`policy\s*=\s*"([^"]+)"`)
	quotedValueRe     = regexp.MustCompile(`"([^"]+)"`)
	templateTokenRe   = regexp.MustCompile(`\{\{\s*([^}]+?)\s*\}\}`)
)

type policyRule struct {
	PolicyName   string          `json:"policy_name"`
	PathPattern  string          `json:"path_pattern"`
	Capabilities map[string]bool `json:"-"`
	CapsList     []string        `json:"capabilities"`
}

type targetPathSpec struct {
	Path         string   `json:"path"`
	RequiredCaps []string `json:"required_capabilities"`
	Required     bool     `json:"required"`
	Source       string   `json:"source"`
}

type pathAccessResult struct {
	Path         string   `json:"path"`
	RequiredCaps []string `json:"required_capabilities"`
	Required     bool     `json:"required"`
	Source       string   `json:"source"`
	Status       string   `json:"status"`
	Reasons      []string `json:"reasons"`
}

type roleAccessResult struct {
	Mount        string             `json:"mount"`
	RoleName     string             `json:"role_name"`
	Policies     []string           `json:"policies"`
	AccessStatus string             `json:"access_status"`
	PathResults  []pathAccessResult `json:"path_results"`
	Reasons      []string           `json:"reasons"`
}

type pathEvaluation struct {
	exactAllow       bool
	exactDeny        bool
	conditionalAllow bool
	conditionalDeny  bool
	reasons          []string
}

// AnalyzeSecretAccess creates a tool for evaluating which auth roles can access a Vault API path.
func AnalyzeSecretAccess(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("analyze_secret_access",
			mcp.WithDescription("Analyze which auth roles can access a Vault API path. Supports conditional evaluation for ACL policy templates (for example {{ identity.entity.aliases.<accessor>.metadata.<key> }}). For KV v2 paths, can automatically evaluate data/metadata ACL paths."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
					ReadOnlyHint:   utils.ToBoolPtr(true),
				},
			),
			mcp.WithString("target_path",
				mcp.DefaultString(""),
				mcp.Description("Vault API path to analyze (for example 'sys/mounts' or 'kv/tenant-2/secret'). For KV v2 shorthand secret paths, the tool can expand to data/metadata ACL paths.")),
			mcp.WithString("required_capabilities",
				mcp.DefaultString("read"),
				mcp.Description("Comma-separated capabilities required on target_path (for example 'read' or 'update,read').")),
			mcp.WithBoolean("include_kv_v2_paths",
				mcp.DefaultBool(true),
				mcp.Description("When true, expands KV v2 shorthand/related paths to include data/metadata ACL checks.")),
			mcp.WithString("namespace",
				mcp.DefaultString(""),
				mcp.Description("Namespace path (for example 'admin/'). Defaults to current namespace.")),
			mcp.WithObject("template_values",
				mcp.Description("Optional map used to resolve policy template tokens. Keys must match full token text inside {{ ... }} (for example identity.entity.aliases.auth_jwt_x.metadata.project).")),

			// Backward-compatible legacy parameters.
			mcp.WithString("mount",
				mcp.DefaultString(""),
				mcp.Description("Deprecated: use target_path instead. Mount path of a KV secret (for example 'kv').")),
			mcp.WithString("secret_path",
				mcp.DefaultString(""),
				mcp.Description("Deprecated: use target_path instead. Secret path under mount (for example 'tenant-2/secret').")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return analyzeSecretAccessHandler(ctx, req, logger)
		},
	}
}

func analyzeSecretAccessHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling analyze_secret_access request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	namespace, _ := args["namespace"].(string)
	templateValues := parseTemplateValues(args["template_values"])
	includeKVV2 := parseBoolArg(args, "include_kv_v2_paths", true)
	requiredCaps := parseCapabilitiesArg(args)

	targetPath, _ := args["target_path"].(string)
	targetPath = normalizeVaultPath(targetPath)

	var warnings []string
	if targetPath == "" {
		mount, _ := args["mount"].(string)
		secretPath, _ := args["secret_path"].(string)
		mount = normalizeVaultPath(mount)
		secretPath = normalizeVaultPath(secretPath)
		if mount != "" && secretPath != "" {
			targetPath = fmt.Sprintf("%s/%s", mount, secretPath)
			warnings = append(warnings, "Using deprecated mount+secret_path arguments. Prefer target_path.")
		}
	}

	if targetPath == "" {
		return mcp.NewToolResultError("target_path is required (or provide both deprecated mount and secret_path)"), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	nsClient := vault
	if namespace != "" {
		nsClient = vault.WithNamespace(namespace)
	}

	mounts, err := nsClient.Sys().ListMounts()
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("Failed to list mounts for KV v2 expansion: %v", err))
		mounts = map[string]*api.MountOutput{}
	}

	targetSpecs := expandTargetPaths(targetPath, requiredCaps, includeKVV2, mounts)

	auths, err := nsClient.Sys().ListAuth()
	if err != nil {
		logger.WithError(err).Error("Failed to list auth methods")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list auth methods: %v", err)), nil
	}

	authMounts := make([]string, 0, len(auths))
	for mountPath := range auths {
		authMounts = append(authMounts, normalizeVaultPath(mountPath))
	}
	sort.Strings(authMounts)

	var roleResults []roleAccessResult

	for _, authMount := range authMounts {
		roleNames, err := listRoleNames(nsClient, authMount)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Skipped auth/%s/role listing: %v", authMount, err))
			continue
		}

		defaultRole, defaultRoleErr := readDefaultRole(nsClient, authMount)
		if defaultRoleErr == nil && defaultRole != "" {
			roleNames = append(roleNames, defaultRole)
		}

		roleNames = uniqueStrings(roleNames)
		sort.Strings(roleNames)

		for _, roleName := range roleNames {
			roleData, err := readRoleData(nsClient, authMount, roleName)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("Skipped auth/%s/role/%s read: %v", authMount, roleName, err))
				continue
			}

			policyNames := extractPolicyNames(roleData)
			if len(policyNames) == 0 {
				roleResults = append(roleResults, roleAccessResult{
					Mount:        authMount,
					RoleName:     roleName,
					Policies:     []string{},
					AccessStatus: "denied",
					PathResults:  buildNoPolicyPathResults(targetSpecs),
					Reasons:      []string{"Role has no attached token policies."},
				})
				continue
			}

			rules, policyWarnings := readPolicyRules(nsClient, policyNames)
			warnings = append(warnings, policyWarnings...)

			pathResults := make([]pathAccessResult, 0, len(targetSpecs))
			reasons := make([]string, 0)
			for _, spec := range targetSpecs {
				eval := evaluatePathAccess(rules, spec.Path, spec.RequiredCaps, templateValues)
				status := pathStatus(eval)
				pathResult := pathAccessResult{
					Path:         spec.Path,
					RequiredCaps: spec.RequiredCaps,
					Required:     spec.Required,
					Source:       spec.Source,
					Status:       status,
					Reasons:      uniqueStrings(eval.reasons),
				}
				if len(pathResult.Reasons) == 0 {
					pathResult.Reasons = []string{"No policy path rules matched this path for required capabilities."}
				}
				pathResults = append(pathResults, pathResult)
				reasons = append(reasons, pathResult.Reasons...)
			}

			roleResults = append(roleResults, roleAccessResult{
				Mount:        authMount,
				RoleName:     roleName,
				Policies:     policyNames,
				AccessStatus: aggregateRoleStatus(pathResults),
				PathResults:  pathResults,
				Reasons:      uniqueStrings(reasons),
			})
		}
	}

	sort.Slice(roleResults, func(i, j int) bool {
		if roleResults[i].AccessStatus == roleResults[j].AccessStatus {
			if roleResults[i].Mount == roleResults[j].Mount {
				return roleResults[i].RoleName < roleResults[j].RoleName
			}
			return roleResults[i].Mount < roleResults[j].Mount
		}
		return roleResults[i].AccessStatus < roleResults[j].AccessStatus
	})

	summary := map[string]int{
		"allowed":     0,
		"conditional": 0,
		"denied":      0,
	}
	for _, r := range roleResults {
		summary[r.AccessStatus]++
	}

	result := map[string]interface{}{
		"target_path":           targetPath,
		"required_capabilities": requiredCaps,
		"include_kv_v2_paths":   includeKVV2,
		"namespace":             namespace,
		"evaluated_paths":       targetSpecs,
		"template_values":       templateValues,
		"summary":               summary,
		"roles":                 roleResults,
	}
	if len(warnings) > 0 {
		result["warnings"] = uniqueStrings(warnings)
	}

	jsonResult, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		logger.WithError(err).Error("Failed to marshal result")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonResult)), nil
}

func expandTargetPaths(targetPath string, requiredCaps []string, includeKVV2 bool, mounts map[string]*api.MountOutput) []targetPathSpec {
	targetPath = normalizeVaultPath(targetPath)
	specs := []targetPathSpec{
		{
			Path:         targetPath,
			RequiredCaps: requiredCaps,
			Required:     true,
			Source:       "input",
		},
	}

	if !includeKVV2 {
		return specs
	}

	mountName, suffix, isKVV2 := matchKVV2Mount(targetPath, mounts)
	if !isKVV2 {
		return specs
	}

	if suffix == "" {
		return specs
	}

	parts := strings.SplitN(suffix, "/", 2)
	firstPart := parts[0]
	rest := ""
	if len(parts) == 2 {
		rest = normalizeVaultPath(parts[1])
	}

	// Explicit KVv2 data path: keep input and add optional metadata path.
	if firstPart == "data" && rest != "" {
		metadataPath := fmt.Sprintf("%s/metadata/%s", mountName, rest)
		return uniquePathSpecs(append(specs, targetPathSpec{
			Path:         metadataPath,
			RequiredCaps: []string{"read", "list"},
			Required:     false,
			Source:       "kv_v2_metadata_companion",
		}))
	}

	// Explicit KVv2 metadata path: keep input and add optional data path.
	if firstPart == "metadata" && rest != "" {
		dataPath := fmt.Sprintf("%s/data/%s", mountName, rest)
		return uniquePathSpecs(append(specs, targetPathSpec{
			Path:         dataPath,
			RequiredCaps: []string{"read"},
			Required:     false,
			Source:       "kv_v2_data_companion",
		}))
	}

	// Shorthand secret path under KVv2 mount.
	dataPath := fmt.Sprintf("%s/data/%s", mountName, suffix)
	metadataPath := fmt.Sprintf("%s/metadata/%s", mountName, suffix)
	return uniquePathSpecs([]targetPathSpec{
		{
			Path:         dataPath,
			RequiredCaps: requiredCaps,
			Required:     true,
			Source:       "kv_v2_data",
		},
		{
			Path:         metadataPath,
			RequiredCaps: []string{"read", "list"},
			Required:     false,
			Source:       "kv_v2_metadata",
		},
	})
}

func matchKVV2Mount(targetPath string, mounts map[string]*api.MountOutput) (string, string, bool) {
	targetPath = normalizeVaultPath(targetPath)

	mountNames := make([]string, 0, len(mounts))
	for mountPath, mountInfo := range mounts {
		if !isKVV2Mount(mountInfo) {
			continue
		}
		mountName := normalizeVaultPath(mountPath)
		if mountName != "" {
			mountNames = append(mountNames, mountName)
		}
	}

	sort.Slice(mountNames, func(i, j int) bool {
		return len(mountNames[i]) > len(mountNames[j])
	})

	for _, mountName := range mountNames {
		if targetPath == mountName {
			return mountName, "", true
		}
		prefix := mountName + "/"
		if strings.HasPrefix(targetPath, prefix) {
			return mountName, normalizeVaultPath(strings.TrimPrefix(targetPath, prefix)), true
		}
	}

	return "", "", false
}

func isKVV2Mount(mountInfo *api.MountOutput) bool {
	if mountInfo == nil {
		return false
	}
	if mountInfo.Type != "kv" {
		return false
	}
	if mountInfo.Options == nil {
		return false
	}
	return mountInfo.Options["version"] == "2"
}

func aggregateRoleStatus(pathResults []pathAccessResult) string {
	if len(pathResults) == 0 {
		return "denied"
	}

	allRequiredAllowed := true
	hasRequiredConditional := false

	for _, r := range pathResults {
		if !r.Required {
			continue
		}
		switch r.Status {
		case "denied":
			return "denied"
		case "conditional":
			hasRequiredConditional = true
			allRequiredAllowed = false
		case "allowed":
		default:
			allRequiredAllowed = false
		}
	}

	if hasRequiredConditional {
		return "conditional"
	}
	if allRequiredAllowed {
		return "allowed"
	}
	return "denied"
}

func buildNoPolicyPathResults(targetSpecs []targetPathSpec) []pathAccessResult {
	results := make([]pathAccessResult, 0, len(targetSpecs))
	for _, spec := range targetSpecs {
		results = append(results, pathAccessResult{
			Path:         spec.Path,
			RequiredCaps: spec.RequiredCaps,
			Required:     spec.Required,
			Source:       spec.Source,
			Status:       "denied",
			Reasons:      []string{"Role has no attached token policies."},
		})
	}
	return results
}

func uniquePathSpecs(specs []targetPathSpec) []targetPathSpec {
	seen := map[string]struct{}{}
	out := make([]targetPathSpec, 0, len(specs))
	for _, spec := range specs {
		key := fmt.Sprintf("%s|%t|%s|%s", normalizeVaultPath(spec.Path), spec.Required, strings.Join(spec.RequiredCaps, ","), spec.Source)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		spec.Path = normalizeVaultPath(spec.Path)
		spec.RequiredCaps = uniqueStrings(spec.RequiredCaps)
		sort.Strings(spec.RequiredCaps)
		out = append(out, spec)
	}
	return out
}

func parseCapabilitiesArg(args map[string]interface{}) []string {
	raw, _ := args["required_capabilities"].(string)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{"read"}
	}
	parts := strings.Split(raw, ",")
	caps := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			caps = append(caps, p)
		}
	}
	caps = uniqueStrings(caps)
	if len(caps) == 0 {
		return []string{"read"}
	}
	sort.Strings(caps)
	return caps
}

func parseBoolArg(args map[string]interface{}, key string, defaultVal bool) bool {
	v, ok := args[key]
	if !ok {
		return defaultVal
	}
	b, ok := v.(bool)
	if !ok {
		return defaultVal
	}
	return b
}

func listRoleNames(nsClient *api.Client, mount string) ([]string, error) {
	secret, err := nsClient.Logical().List(fmt.Sprintf("auth/%s/role", mount))
	if err != nil {
		return nil, err
	}

	if secret == nil || secret.Data == nil {
		return nil, nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, nil
	}

	roleNames := make([]string, 0, len(keys))
	for _, k := range keys {
		name, ok := k.(string)
		if !ok {
			continue
		}
		roleNames = append(roleNames, strings.TrimSuffix(name, "/"))
	}

	return roleNames, nil
}

func readDefaultRole(nsClient *api.Client, mount string) (string, error) {
	secret, err := nsClient.Logical().Read(fmt.Sprintf("auth/%s/config", mount))
	if err != nil || secret == nil || secret.Data == nil {
		return "", err
	}

	defaultRole, _ := secret.Data["default_role"].(string)
	return strings.TrimSpace(defaultRole), nil
}

func readRoleData(nsClient *api.Client, mount, roleName string) (map[string]interface{}, error) {
	secret, err := nsClient.Logical().Read(fmt.Sprintf("auth/%s/role/%s", mount, roleName))
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("role not found")
	}
	return secret.Data, nil
}

func readPolicyRules(nsClient *api.Client, policyNames []string) ([]policyRule, []string) {
	var rules []policyRule
	var warnings []string

	for _, policyName := range policyNames {
		content, err := nsClient.Sys().GetPolicy(policyName)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Failed to read policy %q: %v", policyName, err))
			continue
		}
		if strings.TrimSpace(content) == "" {
			warnings = append(warnings, fmt.Sprintf("Policy %q was empty.", policyName))
			continue
		}
		rules = append(rules, parsePolicyRules(policyName, content)...)
	}

	return rules, warnings
}

func parsePolicyRules(policyName, content string) []policyRule {
	matches := policyPathBlockRe.FindAllStringSubmatch(content, -1)
	rules := make([]policyRule, 0, len(matches))

	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		pathPattern := normalizeVaultPath(match[1])
		block := match[2]
		caps := extractCapabilities(block)
		if len(caps) == 0 {
			continue
		}
		rules = append(rules, policyRule{
			PolicyName:   policyName,
			PathPattern:  pathPattern,
			Capabilities: caps,
			CapsList:     sortedCapabilities(caps),
		})
	}

	return rules
}

func extractCapabilities(policyBlock string) map[string]bool {
	caps := make(map[string]bool)

	if capMatch := capabilitiesRe.FindStringSubmatch(policyBlock); len(capMatch) > 1 {
		for _, val := range quotedValueRe.FindAllStringSubmatch(capMatch[1], -1) {
			if len(val) < 2 {
				continue
			}
			caps[strings.TrimSpace(val[1])] = true
		}
	}

	if len(caps) > 0 {
		return caps
	}

	if legacy := legacyPolicyRe.FindStringSubmatch(policyBlock); len(legacy) > 1 {
		switch strings.TrimSpace(legacy[1]) {
		case "deny":
			caps["deny"] = true
		case "read":
			caps["read"] = true
			caps["list"] = true
		case "write":
			caps["create"] = true
			caps["update"] = true
			caps["patch"] = true
			caps["delete"] = true
			caps["read"] = true
			caps["list"] = true
		case "sudo":
			caps["sudo"] = true
		}
	}

	return caps
}

func evaluatePathAccess(rules []policyRule, targetPath string, requiredCaps []string, templateValues map[string]string) pathEvaluation {
	targetPath = normalizeVaultPath(targetPath)
	eval := pathEvaluation{}

	for _, rule := range rules {
		matchType := policyPathMatch(rule.PathPattern, targetPath, templateValues)
		if matchType == "none" {
			continue
		}

		hasDeny := rule.Capabilities["deny"]
		hasRequired := hasAnyCapability(rule.Capabilities, requiredCaps)
		if !hasDeny && !hasRequired {
			continue
		}

		if hasDeny {
			if matchType == "exact" {
				eval.exactDeny = true
			} else {
				eval.conditionalDeny = true
			}
			eval.reasons = append(eval.reasons, fmt.Sprintf("%s match deny via policy %q path %q", matchType, rule.PolicyName, rule.PathPattern))
		}

		if hasRequired {
			if matchType == "exact" {
				eval.exactAllow = true
			} else {
				eval.conditionalAllow = true
			}
			eval.reasons = append(eval.reasons, fmt.Sprintf("%s match allow via policy %q path %q (%s)", matchType, rule.PolicyName, rule.PathPattern, strings.Join(rule.CapsList, ",")))
		}
	}

	return eval
}

func pathStatus(eval pathEvaluation) string {
	if eval.exactDeny {
		return "denied"
	}
	if eval.exactAllow {
		return "allowed"
	}
	if eval.conditionalAllow || eval.conditionalDeny {
		return "conditional"
	}
	return "denied"
}

func policyPathMatch(pattern, target string, templateValues map[string]string) string {
	pattern = normalizeVaultPath(pattern)
	target = normalizeVaultPath(target)

	resolvedPattern, unresolved := resolvePolicyTemplate(pattern, templateValues)
	if unresolved == 0 {
		if vaultPathMatch(resolvedPattern, target) {
			return "exact"
		}
		return "none"
	}

	wildcardPattern := strings.ReplaceAll(resolvedPattern, "__TEMPLATE__", "*")
	if vaultPathMatch(wildcardPattern, target) {
		return "conditional"
	}
	return "none"
}

func resolvePolicyTemplate(pattern string, templateValues map[string]string) (string, int) {
	unresolved := 0
	resolved := templateTokenRe.ReplaceAllStringFunc(pattern, func(raw string) string {
		match := templateTokenRe.FindStringSubmatch(raw)
		if len(match) < 2 {
			unresolved++
			return "__TEMPLATE__"
		}
		token := strings.TrimSpace(match[1])
		if val, ok := templateValues[token]; ok {
			return normalizeVaultPath(val)
		}
		unresolved++
		return "__TEMPLATE__"
	})
	return resolved, unresolved
}

func vaultPathMatch(pattern, target string) bool {
	pattern = normalizeVaultPath(pattern)
	target = normalizeVaultPath(target)

	var regexBuilder strings.Builder
	regexBuilder.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			regexBuilder.WriteString(".*")
		case '+':
			regexBuilder.WriteString("[^/]+")
		default:
			regexBuilder.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	regexBuilder.WriteString("$")

	re, err := regexp.Compile(regexBuilder.String())
	if err != nil {
		return false
	}
	return re.MatchString(target)
}

func extractPolicyNames(roleData map[string]interface{}) []string {
	policies := make([]string, 0)
	policies = append(policies, toStringSlice(roleData["token_policies"])...)
	policies = append(policies, toStringSlice(roleData["policies"])...)
	policies = uniqueStrings(policies)
	sort.Strings(policies)
	return policies
}

func parseTemplateValues(raw interface{}) map[string]string {
	out := map[string]string{}
	if raw == nil {
		return out
	}
	obj, ok := raw.(map[string]interface{})
	if !ok {
		return out
	}
	for k, v := range obj {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if s, ok := v.(string); ok {
			out[k] = strings.TrimSpace(s)
		}
	}
	return out
}

func toStringSlice(v interface{}) []string {
	switch t := v.(type) {
	case []string:
		return append([]string{}, t...)
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if strings.TrimSpace(t) != "" {
			return []string{t}
		}
	}
	return nil
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}

func sortedCapabilities(caps map[string]bool) []string {
	list := make([]string, 0, len(caps))
	for cap := range caps {
		list = append(list, cap)
	}
	sort.Strings(list)
	return list
}

func hasAnyCapability(caps map[string]bool, required []string) bool {
	for _, cap := range required {
		if caps[cap] {
			return true
		}
	}
	return false
}

func normalizeVaultPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimSuffix(p, "/")
	return p
}
