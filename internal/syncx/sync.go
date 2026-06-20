// Package syncx 는 로컬 ~/.ssh/config 를 파싱하고 도달성을 프로브해
// 중앙 인벤토리로 upsert 할 store.Server 목록을 만든다.
//
// 부트스트랩 용도다 — 최초에 중앙 DB 를 채울 때, 그리고 주기적 정합에 쓴다.
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

// Parse 는 ~/.ssh/config 에서 Host 블록을 읽는다(대소문자 무시).
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

func splitKV(line string) (string, string, bool) {
	key, vals, ok := splitFields(line)
	if !ok {
		return "", "", false
	}
	return key, vals[0], true
}

func splitFields(line string) (string, []string, bool) {
	// "Key Value" 또는 "Key=Value"
	if i := strings.IndexAny(line, " \t="); i > 0 {
		key := line[:i]
		val := strings.TrimSpace(strings.TrimLeft(line[i:], " \t="))
		vals := strings.Fields(val)
		return key, vals, len(vals) > 0
	}
	return "", nil, false
}

// DefaultConfigPath 는 ~/.ssh/config 경로다.
func DefaultConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh", "config")
}

// Build 는 prefix(예: "sre")로 시작하는 alias 만 골라 프로브 후 Server 목록을 만든다.
// alias→hostName 매핑으로 proxyJump 도 IP 가 아닌 인벤토리 hostname 으로 연결한다.
func Build(blocks []hostBlock, prefix string, probeTimeout time.Duration) []store.Server {
	return BuildWithOptions(blocks, BuildOptions{Prefix: prefix, ProbeTimeout: probeTimeout})
}

func BuildWithOptions(blocks []hostBlock, opts BuildOptions) []store.Server {
	opts = opts.withDefaults()

	byAlias := indexByAlias(blocks)
	filtered := filterByPrefix(blocks, opts.Prefix)
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

// classifyDC 는 IP 대역으로 DC 를 추정한다(SRE 환경 휴리스틱).
func classifyDC(ip string) string {
	return classifyDCWithRules(ip, DefaultDCRules())
}

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
