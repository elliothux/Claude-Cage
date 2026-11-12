package managedproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
	"golang.org/x/net/http/httpguts"
)

// NodeIssue contains display metadata only, never node credentials or field values.
type NodeIssue struct {
	Index  int    `json:"index"`
	Name   string `json:"name,omitempty"`
	Type   string `json:"type,omitempty"`
	Reason string `json:"reason"`
}

// Parse enforces Cage's import boundaries. Call Validate before committing a
// candidate source; protocol parameters are interpreted by the bundled core.
// Store.Import also retains skipped-node details.
func Parse(data []byte, sourceID string) ([]Node, error) {
	nodes, _, err := parseNodes(data, sourceID)
	return nodes, err
}

// Node-only import keeps remote files from changing listeners, routes, or file paths.
func parseNodes(data []byte, sourceID string) ([]Node, []NodeIssue, error) {
	if len(data) == 0 || len(data) > MaxImport {
		return nil, nil, errors.New("配置为空或超过 8 MiB")
	}
	var input struct {
		Proxies []map[string]any `yaml:"proxies"`
		Payload []map[string]any `yaml:"payload"`
	}
	if yaml.Unmarshal(data, &input) != nil {
		return nil, nil, errors.New("无法读取 YAML，请导入 Clash/Mihomo 节点订阅或配置；暂不支持 Base64 列表或分享链接")
	}
	proxies := input.Proxies
	if len(proxies) == 0 {
		proxies = input.Payload
	}
	if len(proxies) == 0 || len(proxies) > 3000 {
		return nil, nil, errors.New("配置需要包含 1–3000 个 proxies 节点；仅含远程 provider 的配置请改为导入节点订阅链接")
	}
	types := map[string]bool{}
	for _, k := range strings.Fields("http socks5 ss ssr vmess vless trojan hysteria hysteria2 tuic anytls mieru ssh") {
		types[k] = true
	}
	counts := map[string]int{}
	keyErrors := make([]error, len(proxies))
	for i, p := range proxies {
		// Canonicalize only fields Cage reads or rewrites. Protocol parameters
		// and opaque maps such as HTTP headers belong to the bundled core.
		keyErrors[i] = normalizeImportKeys(p, "name", "type", "server", "udp", "dialer-proxy")
		name, _ := p["name"].(string)
		counts[name]++
	}
	issues := make([]NodeIssue, len(proxies))
	names := map[string]string{}
	indexes := map[string]int{}
	candidates := make([]Node, 0, len(proxies))
	for i, p := range proxies {
		name, _ := p["name"].(string)
		typ, _ := p["type"].(string)
		server, _ := p["server"].(string)
		issue := NodeIssue{Index: i + 1}
		if len(name) <= 240 {
			issue.Name = name
		}
		if types[typ] {
			issue.Type = typ
		}
		switch {
		case keyErrors[i] != nil:
			issue.Reason = keyErrors[i].Error()
		case strings.TrimSpace(name) == "" || len(name) > 240:
			issue.Reason = "节点名称为空或过长"
		case counts[name] > 1:
			issue.Reason = "节点名称重复，无法确定代理链引用"
		case !types[typ]:
			issue.Reason = "节点协议暂不支持"
		case server == "" || len(server) > 253:
			issue.Reason = "节点服务器缺失或过长"
		default:
			if err := normalizeWebSocket(p); err != nil {
				issue.Reason = err.Error()
			} else if typ == "ssh" && sshPrivateKeyPath(p) {
				issue.Reason = "SSH 节点的 private-key 必须直接填写私钥内容，不能引用本机文件"
			} else if unsafeOption(withoutSSHPrivateKey(p)) {
				issue.Reason = "节点不能引用本机文件、网络接口或额外路由"
			} else if typ == "hysteria2" {
				if err := normalizeHysteria2(p); err != nil {
					issue.Reason = err.Error()
				}
			}
		}
		issues[i] = issue
		if issue.Reason != "" {
			continue
		}
		h := sha256.Sum256([]byte(sourceID + "\x00" + name))
		id := hex.EncodeToString(h[:12])
		names[name], indexes[id] = id, i
		candidates = append(candidates, Node{ID: id, Name: name, Type: typ, Config: p})
	}
	byID := map[string]Node{}
	for _, n := range candidates {
		p := n.Config
		p["name"], p["udp"] = n.ID, false
		if v, exists := p["dialer-proxy"]; exists {
			target, ok := v.(string)
			if !ok || names[target] == "" {
				issues[indexes[n.ID]].Reason = "代理链必须引用同一来源中成功导入的具体节点，不能引用 DIRECT 或选择分组"
			} else {
				p["dialer-proxy"] = names[target]
			}
		}
		byID[n.ID] = n
	}
	// Resolve every dependency before retaining nodes. Dropping a failed dialer
	// would silently remove a transit hop; its dependents must be skipped too.
	state := map[string]int{}
	var usable func(string) bool
	usable = func(id string) bool {
		i := indexes[id]
		if issues[i].Reason != "" {
			return false
		}
		if state[id] == 2 {
			return true
		}
		if state[id] == 1 {
			issues[i].Reason = "代理链存在循环"
			return false
		}
		state[id] = 1
		if target, _ := byID[id].Config["dialer-proxy"].(string); target != "" && !usable(target) {
			if issues[i].Reason == "" {
				issues[i].Reason = "代理链依赖的中转节点不可用或存在循环"
			}
			return false
		}
		state[id] = 2
		return true
	}
	out := make([]Node, 0, len(candidates))
	for _, n := range candidates {
		if usable(n.ID) {
			out = append(out, n)
		}
	}
	skipped := []NodeIssue{}
	for _, issue := range issues {
		if issue.Reason != "" {
			skipped = append(skipped, issue)
		}
	}
	if len(out) == 0 {
		var details []string
		for _, issue := range skipped[:min(3, len(skipped))] {
			details = append(details, fmt.Sprintf("第 %d 个节点 %q：%s", issue.Index, issue.Name, issue.Reason))
		}
		return nil, skipped, fmt.Errorf("没有可导入的节点，已跳过 %d 个；%s", len(skipped), strings.Join(details, "；"))
	}
	return out, skipped, nil
}

// Mihomo's decoder matches keys case-insensitively and treats '_' as '-'.
func optionKey(key string) string {
	return strings.ToLower(strings.ReplaceAll(key, "_", "-"))
}

func normalizeImportKeys(p map[string]any, keys ...string) error {
	for _, canonical := range keys {
		found := ""
		for key := range p {
			if optionKey(key) != optionKey(canonical) {
				continue
			}
			if found != "" {
				return fmt.Errorf("节点字段 %s 存在重复写法，请仅保留一种", canonical)
			}
			found = key
		}
		if found != "" && found != canonical {
			p[canonical] = p[found]
			delete(p, found)
		}
	}
	return nil
}

// The core reads private-key as a file path unless the value contains
// "PRIVATE KEY". Only inline key content keeps imports away from local files.
func sshPrivateKeyPath(p map[string]any) bool {
	if normalizeImportKeys(p, "private-key") != nil {
		return true
	}
	raw, exists := p["private-key"]
	if !exists {
		return false
	}
	key, ok := raw.(string)
	return !ok || !strings.Contains(key, "PRIVATE KEY")
}

// withoutSSHPrivateKey exempts only an SSH node's inline top-level key from the
// file checks; nested options and every other protocol keep the full checks.
func withoutSSHPrivateKey(p map[string]any) map[string]any {
	if p["type"] != "ssh" {
		return p
	}
	if _, exists := p["private-key"]; !exists {
		return p
	}
	clone := maps.Clone(p)
	delete(clone, "private-key")
	return clone
}

func normalizeHysteria2(p map[string]any) error {
	if err := normalizeImportKeys(p, "mport", "ports", "pinSHA256", "fingerprint"); err != nil {
		return err
	}
	for _, alias := range []struct {
		from, to  string
		normalize func(any) (string, error)
	}{
		{"mport", "ports", hysteria2Ports},
		{"pinSHA256", "fingerprint", hysteria2Pin},
	} {
		raw, exists := p[alias.from]
		if !exists {
			continue
		}
		value, err := alias.normalize(raw)
		if err != nil {
			return fmt.Errorf("Hysteria2 字段 %s 无效，未忽略该字段", alias.from)
		}
		if current, exists := p[alias.to]; exists {
			canonical, err := alias.normalize(current)
			if err != nil || canonical != value {
				return fmt.Errorf("Hysteria2 字段 %s 与 %s 冲突", alias.from, alias.to)
			}
		}
		p[alias.to] = value
		delete(p, alias.from)
	}
	return nil
}

// Legacy WebSocket fields are accepted by the core but ignored by its transport.
// Normalize only nodes carrying aliases, leaving other protocol options alone.
func normalizeWebSocket(p map[string]any) error {
	legacy := false
	for key := range p {
		if optionKey(key) == "ws-path" || optionKey(key) == "ws-headers" {
			legacy = true
		}
	}
	if !legacy {
		return nil
	}
	if err := normalizeImportKeys(p, "ws-path", "ws-headers", "ws-opts", "network"); err != nil {
		return err
	}
	if p["type"] != "vmess" && p["type"] != "vless" && p["type"] != "trojan" {
		return errors.New("旧 WebSocket 字段仅适用于 VMess、VLESS 或 Trojan 节点")
	}
	if p["network"] != "ws" {
		return errors.New("旧 WebSocket 字段需要显式设置 network: ws，请核对节点传输方式")
	}
	opts := map[string]any{}
	if raw, exists := p["ws-opts"]; exists {
		current, ok := raw.(map[string]any)
		if !ok {
			return errors.New("WebSocket 字段 ws-opts 无效，未忽略旧字段")
		}
		opts = maps.Clone(current)
	}
	if err := normalizeImportKeys(opts, "path", "headers"); err != nil {
		return err
	}
	if raw, exists := p["ws-path"]; exists {
		path, ok := raw.(string)
		if !ok {
			return errors.New("WebSocket 字段 ws-path 无效，未忽略该字段")
		}
		if current, exists := opts["path"]; exists && current != path {
			return errors.New("WebSocket 字段 ws-path 与 ws-opts.path 冲突")
		}
		opts["path"] = path
		delete(p, "ws-path")
	}
	if raw, exists := p["ws-headers"]; exists {
		headers, err := webSocketHeaders(raw)
		if err != nil {
			return err
		}
		if current, exists := opts["headers"]; exists {
			modern, err := webSocketHeaders(current)
			if err != nil {
				return err
			}
			for key, value := range modern {
				if previous, exists := headers[key]; exists && previous != value {
					return errors.New("WebSocket 字段 ws-headers 与 ws-opts.headers 冲突")
				}
				headers[key] = value
			}
		}
		opts["headers"] = headers
		delete(p, "ws-headers")
	}
	p["ws-opts"] = opts
	return nil
}

func webSocketHeaders(raw any) (map[string]any, error) {
	input, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("WebSocket 请求头必须为字符串映射，未忽略该字段")
	}
	headers := make(map[string]any, len(input))
	for key, rawValue := range input {
		value, ok := rawValue.(string)
		if !ok || !httpguts.ValidHeaderFieldName(key) || !httpguts.ValidHeaderFieldValue(value) {
			return nil, errors.New("WebSocket 请求头无效，未忽略该字段")
		}
		key = http.CanonicalHeaderKey(key)
		if previous, exists := headers[key]; exists && previous != value {
			return nil, errors.New("WebSocket 请求头存在大小写不同的冲突写法")
		}
		headers[key] = value
	}
	return headers, nil
}

func hysteria2Ports(raw any) (string, error) {
	var ports string
	switch v := raw.(type) {
	case string:
		ports = strings.TrimSpace(v)
	case int:
		ports = strconv.Itoa(v)
	}
	parts := strings.Split(strings.ReplaceAll(ports, "/", ","), ",")
	if ports == "" || len(parts) > 28 {
		return "", errors.New("invalid ports")
	}
	for i, part := range parts {
		rangeParts := strings.Split(strings.TrimSpace(part), "-")
		if len(rangeParts) > 2 {
			return "", errors.New("invalid port range")
		}
		for j, port := range rangeParts {
			n, err := strconv.Atoi(strings.TrimSpace(port))
			if err != nil || n < 1 || n > 65535 {
				return "", errors.New("invalid port")
			}
			rangeParts[j] = strconv.Itoa(n)
		}
		parts[i] = strings.Join(rangeParts, "-")
	}
	return strings.Join(parts, ","), nil
}

func hysteria2Pin(raw any) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", errors.New("invalid pin")
	}
	value = strings.TrimSpace(strings.ReplaceAll(value, ":", ""))
	pin, err := hex.DecodeString(value)
	if err != nil || len(pin) != sha256.Size {
		return "", errors.New("invalid pin")
	}
	return hex.EncodeToString(pin), nil
}
