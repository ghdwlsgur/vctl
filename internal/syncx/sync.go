// Package syncx parses ~/.ssh/config and probes hosts to build inventory rows.
//
// It is used for initial bootstrap and periodic inventory reconciliation.
package syncx

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

const (
	defaultUser             = "ubuntu"
	defaultCARole           = "sre-core"
	defaultProbeTimeout     = 3 * time.Second
	defaultProbeConcurrency = 32
	maxProbeConcurrency     = 128
)

type DCRule struct {
	Name     string   `yaml:"name"`
	Prefixes []string `yaml:"prefixes"`
}

type BuildOptions struct {
	Prefix           string
	DefaultUser      string
	CARole           string
	ProbeTimeout     time.Duration
	ProbeConcurrency int
	DCRules          []DCRule
}

type hostBlock struct {
	alias     string
	hostName  string
	user      string
	port      int
	proxyJump string // ssh config alias
}

type probeResult struct {
	alias string
	up    *time.Time
}

// Parse reads Host blocks from an ssh config file.
func Parse(path string) ([]hostBlock, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var blocks []hostBlock
	var cur *hostBlock
	var aliases []string
	flush := func() {
		if cur != nil && cur.hostName != "" {
			for _, alias := range aliases {
				if strings.ContainsAny(alias, "*?") {
					continue
				}
				next := *cur
				next.alias = alias
				blocks = append(blocks, next)
			}
		}
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, vals, ok := splitFields(line)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "host":
			flush()
			aliases = vals
			cur = &hostBlock{port: 22}
		case "hostname":
			if cur != nil {
				cur.hostName = vals[0]
			}
		case "user":
			if cur != nil {
				cur.user = vals[0]
			}
		case "port":
			if cur != nil {
				if n, err := strconv.Atoi(vals[0]); err == nil {
					cur.port = n
				}
			}
		case "proxyjump":
			if cur != nil {
				cur.proxyJump = vals[0]
			}
		}
	}
	flush()
	return blocks, sc.Err()
}

func splitFields(line string) (string, []string, bool) {
	// Accept both "Key Value" and "Key=Value" formats.
	if i := strings.IndexAny(line, " \t="); i > 0 {
		key := line[:i]
		val := strings.TrimSpace(strings.TrimLeft(line[i:], " \t="))
		vals := strings.Fields(val)
		return key, vals, len(vals) > 0
	}
	return "", nil, false
}

// DefaultConfigPath returns ~/.ssh/config.
func DefaultConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh", "config")
}

// BuildWithOptions probes aliases with the selected prefix and returns inventory
// rows. ProxyJump aliases are normalized to inventory hostnames.
func BuildWithOptions(blocks []hostBlock, opts BuildOptions) []store.Server {
	opts = opts.withDefaults()

	byAlias := indexByAlias(blocks)
	filtered := filterByPrefix(blocks, opts.Prefix)
	filtered = includeJumpHosts(filtered, byAlias)
	up := probeAll(filtered, opts.ProbeTimeout, opts.ProbeConcurrency)

	var out []store.Server
	for _, b := range filtered {
		out = append(out, buildServer(b, byAlias, up[b.alias], opts))
	}
	return out
}

func indexByAlias(blocks []hostBlock) map[string]hostBlock {
	byAlias := make(map[string]hostBlock, len(blocks))
	for _, b := range blocks {
		byAlias[b.alias] = b
	}
	return byAlias
}

// includeJumpHosts augments the selection with any blocks referenced as a
// ProxyJump (transitively) by an already-included host, even if those jump
// hosts don't match the prefix. Without this, ssh to a host whose jump host
// was filtered out fails with "lookup jump host: no rows in result set".
func includeJumpHosts(selected []hostBlock, byAlias map[string]hostBlock) []hostBlock {
	in := make(map[string]bool, len(selected))
	for _, b := range selected {
		in[b.alias] = true
	}
	// BFS over jump references until no new jump host is added.
	queue := append([]hostBlock(nil), selected...)
	for len(queue) > 0 {
		b := queue[0]
		queue = queue[1:]
		if b.proxyJump == "" {
			continue
		}
		ja := normalizeJumpAlias(b.proxyJump)
		if ja == "" || in[ja] {
			continue
		}
		jb, ok := byAlias[ja]
		if !ok {
			continue // jump host not in ssh config; resolveJumpAlias keeps the raw alias
		}
		in[ja] = true
		selected = append(selected, jb)
		queue = append(queue, jb)
	}
	return selected
}

func filterByPrefix(blocks []hostBlock, prefix string) []hostBlock {
	if prefix == "" {
		return blocks
	}
	filtered := make([]hostBlock, 0, len(blocks))
	prefixLower := strings.ToLower(prefix)
	for _, b := range blocks {
		if strings.HasPrefix(strings.ToLower(b.alias), prefixLower) {
			filtered = append(filtered, b)
		}
	}
	return filtered
}

func buildServer(b hostBlock, byAlias map[string]hostBlock, up *time.Time, opts BuildOptions) store.Server {
	return store.Server{
		Hostname:   b.alias,
		IP:         b.hostName,
		Port:       b.port,
		User:       firstNonEmpty(b.user, opts.DefaultUser),
		JumpVia:    resolveJumpAlias(b.proxyJump, byAlias),
		DC:         classifyDCWithRules(b.hostName, opts.DCRules),
		CARole:     opts.CARole,
		LastSeenUp: up,
	}
}

func resolveJumpAlias(proxyJump string, byAlias map[string]hostBlock) string {
	if proxyJump == "" {
		return ""
	}
	jumpAlias := normalizeJumpAlias(proxyJump)
	if jb, ok := byAlias[jumpAlias]; ok {
		return jb.alias
	}
	return jumpAlias
}

func (o BuildOptions) withDefaults() BuildOptions {
	if o.DefaultUser == "" {
		o.DefaultUser = defaultUser
	}
	if o.CARole == "" {
		o.CARole = defaultCARole
	}
	if o.ProbeTimeout <= 0 {
		o.ProbeTimeout = defaultProbeTimeout
	}
	if o.ProbeConcurrency <= 0 {
		o.ProbeConcurrency = defaultProbeConcurrency
	}
	if o.ProbeConcurrency > maxProbeConcurrency {
		o.ProbeConcurrency = maxProbeConcurrency
	}
	if len(o.DCRules) == 0 {
		o.DCRules = DefaultDCRules()
	}
	return o
}

func DefaultDCRules() []DCRule {
	return []DCRule{
		{Name: "incheon", Prefixes: []string{"10.40.0.", "192.168.10."}},
		{Name: "seoul-onprem", Prefixes: []string{"192.168.201.", "192.168.190.", "192.168.110."}},
	}
}

func probeAll(blocks []hostBlock, timeout time.Duration, concurrency int) map[string]*time.Time {
	if len(blocks) == 0 {
		return nil
	}
	if concurrency > len(blocks) {
		concurrency = len(blocks)
	}

	jobs := make(chan hostBlock)
	results := make(chan probeResult, len(blocks))
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b := range jobs {
				results <- probeOne(b, timeout)
			}
		}()
	}

	go func() {
		for _, b := range blocks {
			jobs <- b
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	out := make(map[string]*time.Time, len(blocks))
	for res := range results {
		out[res.alias] = res.up
	}
	return out
}

func probeOne(b hostBlock, timeout time.Duration) probeResult {
	if !probe(b.hostName, b.port, timeout) {
		return probeResult{alias: b.alias}
	}
	t := time.Now()
	return probeResult{alias: b.alias, up: &t}
}

func normalizeJumpAlias(jump string) string {
	if jump == "" {
		return ""
	}
	if i := strings.Index(jump, ","); i >= 0 {
		jump = jump[:i]
	}
	if i := strings.LastIndex(jump, "@"); i >= 0 {
		jump = jump[i+1:]
	}
	host, _, err := net.SplitHostPort(jump)
	if err == nil {
		return strings.Trim(host, "[]")
	}
	if i := strings.LastIndex(jump, ":"); i > 0 && !strings.Contains(jump[i+1:], ":") {
		return strings.Trim(jump[:i], "[]")
	}
	return strings.Trim(jump, "[]")
}

func probe(host string, port int, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// classifyDCWithRules estimates the DC from configured IP prefixes.
func classifyDCWithRules(ip string, rules []DCRule) string {
	for _, rule := range rules {
		for _, prefix := range rule.Prefixes {
			if prefix != "" && strings.HasPrefix(ip, prefix) {
				return rule.Name
			}
		}
	}
	return "unknown"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
