// Command benchrun runs BenchmarkRead test binaries in interleaved rounds and
// prints the median MB/s and allocs/op of each cell.
//
//	benchrun -rounds 5 -maxload 8 base.test:default base.test:reads new.test:default new.test:reads new.test:pathops
//
// Each argument is binary:mode (BENCH_MODE). Rounds alternate over all the
// configurations, so a drift in machine load hits every one of them alike. It
// refuses to time anything when the 1-minute load average is above -maxload
// and exits 3, so no number is produced under load.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// sample is one benchmark line.
type sample struct {
	cell   string
	mbps   float64
	allocs float64
}

// parseLine reads "BenchmarkRead/<cell>-16  N  x ns/op  y MB/s  z B/op  w allocs/op".
func parseLine(line string) (sample, bool) {
	f := strings.Fields(line)
	if len(f) < 4 || !strings.HasPrefix(f[0], "BenchmarkRead/") {
		return sample{}, false
	}
	name := strings.TrimPrefix(f[0], "BenchmarkRead/")
	if i := strings.LastIndexByte(name, '-'); i >= 0 {
		name = name[:i]
	}
	s := sample{cell: name, mbps: -1, allocs: -1}
	for i := 2; i+1 < len(f); i++ {
		v, err := strconv.ParseFloat(f[i], 64)
		if err != nil {
			continue
		}
		switch f[i+1] {
		case "MB/s":
			s.mbps = v
		case "allocs/op":
			s.allocs = v
		}
	}
	return s, s.mbps >= 0 && s.allocs >= 0
}

func median(v []float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	if len(s) == 0 {
		return 0
	}
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

// load1 returns the 1-minute load average.
func load1() (float64, error) {
	if runtime.GOOS == "linux" {
		b, err := os.ReadFile("/proc/loadavg")
		if err != nil {
			return 0, err
		}
		return strconv.ParseFloat(strings.Fields(string(b))[0], 64)
	}
	out, err := exec.Command("sysctl", "-n", "vm.loadavg").Output()
	if err != nil {
		return 0, err
	}
	f := strings.Fields(strings.Trim(string(out), "{} \n"))
	if len(f) == 0 {
		return 0, errors.New("empty vm.loadavg")
	}
	return strconv.ParseFloat(f[0], 64)
}

type config struct{ bin, mode string }

func (c config) String() string { return c.bin + ":" + c.mode }

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	rounds, maxload, benchtime := 5, 8.0, "1s"
	var cfgs []config
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-rounds", "-maxload", "-benchtime":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "benchrun: missing value for", args[i])
				return 2
			}
			i++
			var err error
			switch args[i-1] {
			case "-rounds":
				rounds, err = strconv.Atoi(args[i])
			case "-maxload":
				maxload, err = strconv.ParseFloat(args[i], 64)
			default:
				benchtime = args[i]
			}
			if err != nil {
				fmt.Fprintln(stderr, "benchrun:", err)
				return 2
			}
		default:
			bin, mode, ok := strings.Cut(args[i], ":")
			if !ok {
				fmt.Fprintln(stderr, "benchrun: want binary:mode, got", args[i])
				return 2
			}
			cfgs = append(cfgs, config{bin, mode})
		}
	}
	if len(cfgs) == 0 {
		fmt.Fprintln(stderr, "usage: benchrun [-rounds n] [-maxload x] [-benchtime d] binary:mode ...")
		return 2
	}
	mbps := map[config]map[string][]float64{}
	allocs := map[config]map[string][]float64{}
	var cells []string
	seen := map[string]bool{}
	var worst float64
	for r := 0; r < rounds; r++ {
		for _, c := range cfgs {
			l, err := load1()
			if err != nil {
				fmt.Fprintln(stderr, "benchrun: load:", err)
				return 1
			}
			if l > maxload {
				fmt.Fprintf(stderr, "benchrun: 1-minute load %.2f is above %.2f: timings skipped\n", l, maxload)
				return 3
			}
			worst = max(worst, l)
			cmd := exec.Command(c.bin, "-test.run", "^$", "-test.bench", "Read", "-test.benchmem", "-test.benchtime", benchtime)
			cmd.Env = append(os.Environ(), "BENCH_MODE="+c.mode)
			cmd.Stdin = nil
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = stderr
			if err := cmd.Run(); err != nil {
				fmt.Fprintf(stderr, "benchrun: %s: %v\n", c, err)
				return 1
			}
			n := 0
			sc := bufio.NewScanner(&out)
			for sc.Scan() {
				s, ok := parseLine(sc.Text())
				if !ok {
					continue
				}
				n++
				if !seen[s.cell] {
					seen[s.cell] = true
					cells = append(cells, s.cell)
				}
				if mbps[c] == nil {
					mbps[c], allocs[c] = map[string][]float64{}, map[string][]float64{}
				}
				mbps[c][s.cell] = append(mbps[c][s.cell], s.mbps)
				allocs[c][s.cell] = append(allocs[c][s.cell], s.allocs)
			}
			if n == 0 {
				fmt.Fprintf(stderr, "benchrun: %s printed no BenchmarkRead line\n", c)
				return 1
			}
		}
	}
	fmt.Fprintf(stdout, "median of %d interleaved rounds, benchtime %s, highest 1-min load %.2f\n\n", rounds, benchtime, worst)
	fmt.Fprintf(stdout, "%-24s", "MB/s (allocs/op)")
	for _, c := range cfgs {
		fmt.Fprintf(stdout, " %22s", c)
	}
	fmt.Fprintln(stdout)
	for _, cell := range cells {
		fmt.Fprintf(stdout, "%-24s", cell)
		for _, c := range cfgs {
			fmt.Fprintf(stdout, " %14.0f (%5.0f)", median(mbps[c][cell]), median(allocs[c][cell]))
		}
		fmt.Fprintln(stdout)
	}
	return 0
}
