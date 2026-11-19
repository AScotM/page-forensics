package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Metric struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
	Unit  string `json:"unit"`
}
type Zone struct {
	Node          int      `json:"node"`
	Name          string   `json:"name"`
	Free          []uint64 `json:"free_by_order"`
	FreePages     uint64   `json:"free_pages"`
	LargestOrder  int      `json:"largest_order"`
	Fragmentation float64  `json:"fragmentation_index"`
}
type Pressure struct {
	Some map[string]float64 `json:"some,omitempty"`
	Full map[string]float64 `json:"full,omitempty"`
}
type Snapshot struct {
	Timestamp time.Time         `json:"timestamp"`
	Host      string            `json:"host"`
	Kernel    string            `json:"kernel"`
	PageSize  uint64            `json:"page_size"`
	VMStat    map[string]uint64 `json:"vmstat"`
	MemInfo   map[string]uint64 `json:"meminfo_kib"`
	Zones     []Zone            `json:"zones"`
	PSI       Pressure          `json:"psi"`
	THP       map[string]string `json:"thp"`
	Findings  []Finding         `json:"findings"`
	Errors    []string          `json:"errors,omitempty"`
}
type Finding struct {
	Level   string `json:"level"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
}
type Options struct {
	Root   string
	Color  bool
	Orders int
}

func read(root, path string) ([]byte, error) {
	return os.ReadFile(filepath.Join(root, strings.TrimPrefix(path, "/")))
}
func keyValues(b []byte) map[string]uint64 {
	m := map[string]uint64{}
	s := bufio.NewScanner(strings.NewReader(string(b)))
	s.Buffer(make([]byte, 4096), 2*1024*1024)
	for s.Scan() {
		f := strings.Fields(strings.ReplaceAll(s.Text(), ":", ""))
		if len(f) < 2 {
			continue
		}
		if n, e := strconv.ParseUint(f[1], 10, 64); e == nil {
			m[f[0]] = n
		}
	}
	return m
}
func parseBuddy(b []byte, orders int) []Zone {
	var z []Zone
	s := bufio.NewScanner(strings.NewReader(string(b)))
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) < 5 || f[0] != "Node" || f[2] != "zone" {
			continue
		}
		node, e := strconv.Atoi(strings.TrimSuffix(f[1], ","))
		if e != nil {
			continue
		}
		name := f[3]
		free := []uint64{}
		var pages uint64
		largest := -1
		for i := 4; i < len(f) && i < orders+4; i++ {
			n, e := strconv.ParseUint(f[i], 10, 64)
			if e != nil {
				break
			}
			free = append(free, n)
			if n > 0 {
				largest = i - 4
			}
			if i-4 < 63 {
				pages += n << uint(i-4)
			}
		}
		if len(free) == 0 {
			continue
		}
		var frag float64
		if pages > 0 && largest >= 0 {
			frag = 100 * (1 - float64(uint64(1)<<uint(largest))/float64(pages))
			frag = math.Max(0, frag)
		}
		z = append(z, Zone{node, name, free, pages, largest, frag})
	}
	sort.Slice(z, func(i, j int) bool {
		if z[i].Node == z[j].Node {
			return z[i].Name < z[j].Name
		}
		return z[i].Node < z[j].Node
	})
	return z
}
func parsePSI(b []byte) Pressure {
	p := Pressure{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		m := map[string]float64{}
		for _, v := range f[1:] {
			pair := strings.SplitN(v, "=", 2)
			if len(pair) == 2 {
				n, e := strconv.ParseFloat(pair[1], 64)
				if e == nil {
					m[pair[0]] = n
				}
			}
		}
		switch f[0] {
		case "some":
			p.Some = m
		case "full":
			p.Full = m
		}
	}
	return p
}
func thp(root string) map[string]string {
	m := map[string]string{}
	for _, p := range []string{"enabled", "defrag", "shmem_enabled", "khugepaged/defrag", "khugepaged/pages_to_scan", "khugepaged/scan_sleep_millisecs"} {
		b, e := read(root, "/sys/kernel/mm/transparent_hugepage/"+p)
		if e == nil {
			m[p] = strings.TrimSpace(string(b))
		}
	}
	return m
}
func capture(o Options) Snapshot {
	host, _ := os.Hostname()
	kernel, _ := read(o.Root, "/proc/sys/kernel/osrelease")
	s := Snapshot{Timestamp: time.Now(), Host: host, Kernel: strings.TrimSpace(string(kernel)), PageSize: uint64(os.Getpagesize()), VMStat: map[string]uint64{}, MemInfo: map[string]uint64{}, THP: thp(o.Root)}
	for _, item := range []struct {
		path   string
		target *map[string]uint64
	}{{"/proc/vmstat", &s.VMStat}, {"/proc/meminfo", &s.MemInfo}} {
		b, e := read(o.Root, item.path)
		if e != nil {
			s.Errors = append(s.Errors, item.path+": "+e.Error())
		} else {
			*item.target = keyValues(b)
		}
	}
	if b, e := read(o.Root, "/proc/buddyinfo"); e == nil {
		s.Zones = parseBuddy(b, o.Orders)
	} else {
		s.Errors = append(s.Errors, "/proc/buddyinfo: "+e.Error())
	}
	if b, e := read(o.Root, "/proc/pressure/memory"); e == nil {
		s.PSI = parsePSI(b)
	}
	s.Findings = diagnose(s)
	return s
}
func diagnose(s Snapshot) []Finding {
	var f []Finding
	add := func(l, sub, msg string) { f = append(f, Finding{l, sub, msg}) }
	total := s.MemInfo["MemTotal"]
	available := s.MemInfo["MemAvailable"]
	if total > 0 {
		pct := 100 * float64(available) / float64(total)
		if pct < 10 {
			add("warning", "available memory", fmt.Sprintf("MemAvailable is %.1f%% of MemTotal; investigate reclaim and workload pressure", pct))
		} else if pct < 20 {
			add("notice", "available memory", fmt.Sprintf("MemAvailable is %.1f%% of MemTotal", pct))
		}
	}
	if v, ok := s.PSI.Some["avg10"]; ok && v > 10 {
		add("warning", "memory PSI", fmt.Sprintf("some avg10 %.2f%% indicates recent memory stalls", v))
	}
	if v, ok := s.PSI.Full["avg10"]; ok && v > 1 {
		add("warning", "memory PSI", fmt.Sprintf("full avg10 %.2f%% indicates concurrent stalls", v))
	}
	for _, z := range s.Zones {
		if z.FreePages == 0 {
			add("notice", fmt.Sprintf("node %d %s", z.Node, z.Name), "No free buddy pages reported; this may be normal for specialized zones")
		}
	}
	if len(s.Zones) == 0 {
		add("notice", "buddy allocator", "No zone data available")
	}
	return f
}
func delta(a, b Snapshot) map[string]uint64 {
	m := map[string]uint64{}
	for k, v := range b.VMStat {
		if prev, ok := a.VMStat[k]; ok && v >= prev {
			m[k] = v - prev
		}
	}
	return m
}
func writeJSON(path string, v any) error {
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		return e
	}
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0644)
}
func writeCSV(path string, s Snapshot) error {
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		return e
	}
	f, e := os.Create(path)
	if e != nil {
		return e
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{"timestamp", "category", "metric", "value", "unit"})
	for _, entry := range []struct {
		name string
		m    map[string]uint64
		unit string
	}{{"vmstat", s.VMStat, "kernel_counter_or_pages"}, {"meminfo", s.MemInfo, "KiB"}} {
		keys := make([]string, 0, len(entry.m))
		for k := range entry.m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			_ = w.Write([]string{s.Timestamp.Format(time.RFC3339Nano), entry.name, k, strconv.FormatUint(entry.m[k], 10), entry.unit})
		}
	}
	for _, z := range s.Zones {
		_ = w.Write([]string{s.Timestamp.Format(time.RFC3339Nano), "buddy", fmt.Sprintf("node%d_%s_free_pages", z.Node, z.Name), strconv.FormatUint(z.FreePages, 10), "pages"})
	}
	w.Flush()
	return w.Error()
}
func c(enabled bool, code string) string {
	if enabled {
		return "\x1b[" + code + "m"
	}
	return ""
}
func bar(v, max float64, width int) string {
	if max <= 0 {
		max = 1
	}
	n := int(math.Round(math.Min(1, math.Max(0, v/max)) * float64(width)))
	return strings.Repeat("█", n) + strings.Repeat("░", width-n)
}
func render(s Snapshot, o Options, prev *Snapshot) {
	cyan := c(o.Color, "38;2;104;206;220")
	gold := c(o.Color, "38;2;241;188;115")
	reset := c(o.Color, "0")
	fmt.Printf("%sPAGE FORENSICS%s  %s  %s  %s\n", cyan, reset, s.Host, s.Kernel, s.Timestamp.Format(time.RFC3339))
	fmt.Println(strings.Repeat("─", 76))
	total := s.MemInfo["MemTotal"]
	avail := s.MemInfo["MemAvailable"]
	fmt.Printf("%sMEMORY%s  total %.2f GiB   available %.2f GiB   page %d bytes\n", gold, reset, float64(total)/1048576, float64(avail)/1048576, s.PageSize)
	if total > 0 {
		fmt.Printf("        available %s %5.1f%%\n", bar(float64(avail), float64(total), 30), 100*float64(avail)/float64(total))
	}
	fmt.Printf("%sPRESSURE%s  some avg10 %.2f%%   full avg10 %.2f%%\n", gold, reset, s.PSI.Some["avg10"], s.PSI.Full["avg10"])
	fmt.Printf("%sBUDDY ALLOCATOR%s\n", gold, reset)
	for _, z := range s.Zones {
		fmt.Printf("  node %-2d zone %-9s free %10d pages  largest order %2d  %s\n", z.Node, z.Name, z.FreePages, z.LargestOrder, bar(float64(z.LargestOrder+1), float64(len(z.Free)), 15))
		fmt.Printf("    orders:")
		for i, n := range z.Free {
			fmt.Printf(" %d:%d", i, n)
		}
		fmt.Println()
	}
	if len(s.THP) > 0 {
		fmt.Printf("%sTRANSPARENT HUGE PAGES%s\n", gold, reset)
		keys := make([]string, 0, len(s.THP))
		for k := range s.THP {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %-28s %s\n", k, s.THP[k])
		}
	}
	keys := []string{"pgfault", "pgmajfault", "pgscan_kswapd", "pgscan_direct", "pgsteal_kswapd", "pgsteal_direct", "compact_stall", "compact_fail", "compact_success", "thp_fault_alloc", "thp_fault_fallback", "pswpin", "pswpout"}
	fmt.Printf("%sVM COUNTERS%s\n", gold, reset)
	d := map[string]uint64{}
	if prev != nil {
		d = delta(*prev, s)
	}
	for _, k := range keys {
		if v, ok := s.VMStat[k]; ok {
			fmt.Printf("  %-24s %14d", k, v)
			if prev != nil {
				fmt.Printf("  +%-10d", d[k])
			}
			fmt.Println()
		}
	}
	if len(s.Findings) > 0 {
		fmt.Printf("%sFINDINGS%s\n", gold, reset)
		for _, f := range s.Findings {
			fmt.Printf("  [%s] %s: %s\n", f.Level, f.Subject, f.Detail)
		}
	}
	for _, e := range s.Errors {
		fmt.Printf("  [unavailable] %s\n", e)
	}
}
func main() {
	var root, output, baseline string
	var interval time.Duration
	var count, orders int
	var jsonOnly, noColor, clear bool
	flag.StringVar(&root, "root", "/", "filesystem root for proc/sys fixtures")
	flag.StringVar(&output, "output", "", "output prefix for JSON and CSV snapshots")
	flag.StringVar(&baseline, "baseline", "", "baseline snapshot JSON for counter comparison")
	flag.DurationVar(&interval, "interval", 0, "sampling interval, e.g. 2s")
	flag.IntVar(&count, "count", 1, "number of samples; 0 means continuous with interval")
	flag.IntVar(&orders, "orders", 32, "maximum buddy orders to parse")
	flag.BoolVar(&jsonOnly, "json", false, "write JSON snapshot to stdout")
	flag.BoolVar(&noColor, "no-color", false, "disable ANSI colors")
	flag.BoolVar(&clear, "clear", false, "clear terminal between samples")
	flag.Parse()
	if orders < 1 || orders > 63 {
		fatal(errors.New("orders must be between 1 and 63"))
	}
	if interval < 0 {
		fatal(errors.New("interval must be nonnegative"))
	}
	if count < 0 {
		fatal(errors.New("count must be nonnegative"))
	}
	if count == 0 && interval == 0 {
		fatal(errors.New("continuous sampling requires -interval"))
	}
	o := Options{root, !noColor && os.Getenv("NO_COLOR") == "" && !jsonOnly, orders}
	var previous *Snapshot
	if baseline != "" {
		b, e := os.ReadFile(baseline)
		if e != nil {
			fatal(e)
		}
		var old Snapshot
		if e = json.Unmarshal(b, &old); e != nil {
			fatal(e)
		}
		previous = &old
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	for i := 0; count == 0 || i < count; i++ {
		select {
		case <-sig:
			return
		default:
		}
		s := capture(o)
		if jsonOnly {
			b, _ := json.Marshal(s)
			fmt.Println(string(b))
		} else {
			if clear && i > 0 {
				fmt.Print("\x1b[2J\x1b[H")
			}
			render(s, o, previous)
		}
		if output != "" {
			prefix := output
			if count != 1 {
				prefix = fmt.Sprintf("%s-%05d", output, i+1)
			}
			if e := writeJSON(prefix+".json", s); e != nil {
				fatal(e)
			}
			if e := writeCSV(prefix+".csv", s); e != nil {
				fatal(e)
			}
		}
		previous = &s
		if interval > 0 && (count == 0 || i+1 < count) {
			select {
			case <-sig:
				return
			case <-time.After(interval):
			}
		}
	}
}
func fatal(e error) { fmt.Fprintln(os.Stderr, "page-forensics:", e); os.Exit(1) }
