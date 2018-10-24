package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/adedayo/cidr"
	tlsaudit "github.com/adedayo/net/tlsaudit/pkg"
	"github.com/adedayo/net/tlsaudit/pkg/model"
	"gopkg.in/urfave/cli.v2"
)

var (
	version = "0.0.0" // deployed version will be taken from release tags
)

func main() {
	app := &cli.App{
		Name:    "tlsaudit",
		Version: version,
		Usage:   "Audit TLS settings on open ports on servers",
		UsageText: `Audit TLS settings on open ports on servers. 
	
Example:
	
tlsaudit 8.8.8.8/32 10.10.10.1/30

`,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "json",
				Aliases: []string{"j"},
				Usage:   "generate JSON output",
			},
			&cli.BoolFlag{
				Name:    "protocols-only",
				Aliases: []string{"p"},
				Usage:   "only check supported protocols (will not do detailed checks on supported ciphers)",
			},
			&cli.BoolFlag{
				Name:    "hide-certs",
				Aliases: []string{"c"},
				Usage:   "suppress certificate information in output",
			},
			&cli.BoolFlag{
				Name:    "quiet",
				Aliases: []string{"q"},
				Usage:   "control whether to produce a running commentary of progress or stay quiet till the end",
			},
			&cli.IntFlag{
				Name:    "timeout",
				Aliases: []string{"t"},
				Usage:   "`TIMEOUT` (in seconds) to adjust how much we are willing to wait for servers to come back with responses. Smaller timeout sacrifices accuracy for speed",
				Value:   5,
			},
			&cli.IntFlag{
				Name:    "rate",
				Aliases: []string{"r"},
				Usage:   "the rate (in packets per second) that we should use to scan for open ports",
				Value:   1000,
			},
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "write results into an output `FILE`",
				Value:   "tlsaudit.txt",
			},
			&cli.StringFlag{
				Name:    "input",
				Aliases: []string{"i"},
				Usage:   "read the CIDR range, IPs and domains to scan from an input `FILE` separated by commas, or newlines",
				Value:   "tlsaudit_input.txt",
			},
		},
		// EnableShellCompletion: true,

		Authors: []*cli.Author{
			&cli.Author{
				Name:  "Adedayo Adetoye (Dayo)",
				Email: "https://github.com/adedayo",
			},
		},

		Action: func(c *cli.Context) error {
			return process(c)
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

}

func process(c *cli.Context) error {
	if c.NArg() == 0 && !c.IsSet("input") {
		c.App.Run([]string{"tlsaudit", "h"})
		return nil
	}
	var args []string

	if c.IsSet("input") {
		args = getCIDRFromFile(c.String("input"))
	} else {
		args = c.Args().Slice()
	}

	//make the input textually unique
	uniqueArgsMap := make(map[string]bool)

	for _, x := range args {
		uniqueArgsMap[x] = true
	}
	args = []string{}
	for x := range uniqueArgsMap {
		args = append(args, x)
	}
	fmt.Printf("TLS Audit (v %s)\nScanning: %s\n", version, strings.Join(args, ", "))
	config := tlsmodel.ScanConfig{
		ProtocolsOnly:    c.Bool("protocols-only"),
		Timeout:          c.Int("timeout"),
		PacketsPerSecond: c.Int("rate"),
		HideCerts:        c.Bool("hide-certs"),
		Quiet:            c.Bool("quiet"),
	}
	scan := make(map[string]tlsmodel.ScanResult)
	totalIPs, processedIPs := 0, 0
	for _, x := range args {
		rng := "/32"
		if strings.Contains(x, "/") {
			rng = "/" + strings.Split(x, "/")[1]
		}
		if strings.Contains(x, ":") {
			x = strings.Split(x, ":")[0] + rng
		} else {
			x = strings.Split(x, "/")[0] + rng
		}
		totalIPs += len(cidr.Expand(x))
	}
	if totalIPs < 1 {
		println("There are no resolvable IPs to process!")
		return nil
	}
	for _, host := range args {
		start := time.Now()
		results := []<-chan tlsmodel.ScanResult{}
		results = append(results, tlsaudit.ScanCIDRTLS(host, config))
		for result := range tlsaudit.MergeResultChannels(results...) {
			key := result.Server + result.Port
			if _, present := scan[key]; !present {
				scan[key] = result
			}
		}
		processedIPs += len(cidr.Expand(host))
		if !config.Quiet {
			fmt.Printf("Finished scan of %s. Progress %f%% %d hosts of a total of %d in %f seconds\n",
				host, 100*float32(processedIPs)/float32(totalIPs), processedIPs, totalIPs, time.Since(start).Seconds())
		}

	}
	var scanResults []tlsmodel.ScanResult
	for k := range scan {
		scanResults = append(scanResults, scan[k])
	}
	sort.Sort(sorter(scanResults))
	if c.Bool("json") {
		outputJSON(scanResults)
	} else {
		outputText(scanResults, config, c)
	}

	return nil
}

func getCIDRFromFile(input string) (args []string) {
	file, err := os.Open(input)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	lines := []string{}
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	for _, line := range lines {
		uncommented := strings.Split(line, "#")[0] //get rid of comments
		for _, arg := range strings.Split(uncommented, ",") {
			v := strings.TrimSpace(arg)
			if v != "" {
				args = append(args, v)
			}
		}
	}
	return
}

func deDuplicate(data *[]string) {
	j := 0
	found := make(map[string]bool)
	for _, x := range *data {
		if !found[x] {
			found[x] = true
			(*data)[j] = x
			j++
		}
	}
	*data = (*data)[:j]
}
func outputJSON(ports []tlsmodel.ScanResult) {
	for _, p := range ports {
		fmt.Printf("%#v\n", p.ToStringStruct())
	}
}

func outputText(results []tlsmodel.ScanResult, config tlsmodel.ScanConfig, c *cli.Context) {
	result := "TLS Audit Results\n"
	currentServer := ""
	for _, r := range results {
		outResult, curServer := generateResultText(r, currentServer)
		result += outResult
		currentServer = curServer
	}
	// textOutput := strings.Replace(result, "|", "", -1)
	textCSV := strings.Replace(strings.Replace(result, ",", ";", -1), "|", ",", -1)
	// println(textOutput)
	// println(result)
	// println(textCSV)

	for _, scan := range results {
		fmt.Printf("%s\n", scan.ToString(config))
	}

	if c.IsSet("output") {
		f, err := os.Create(c.String("output"))
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		defer f.Close()

		_, err = f.WriteString(textCSV)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

	}
}

func generateResultText(r tlsmodel.ScanResult, currentServerInput string) (result, currentServer string) {
	hostName := ""
	format1 := "%-10s| %-15s| %s\n"
	format2 := "%-10s| %-5t%-10s| %s\n"
	format3 := "%-10s| %-15s| %s\n"

	if r.Server != currentServerInput {
		currentServer = r.Server
		h, err := net.LookupAddr(r.Server)
		if err != nil {
			hostName = ""
		} else {
			hostName = fmt.Sprintf("(%s)", strings.Join(h, ", "))
		}
		result += fmt.Sprintf("\n%s %s\n", r.Server, hostName)
		result += fmt.Sprintf(format1, "Open Port", "Supports TLS", "Supported Protocols")
	}
	protocols := ""
	if r.SupportsTLS() {
		supported := []string{}
		for _, p := range r.SupportedProtocols {
			supported = append(supported, tlsmodel.TLSVersionMap[p])
		}
		protocols = strings.Join(supported, ", ")
	}
	startTLS := ""
	if r.IsSTARTLS {
		startTLS = "(STARTTLS)"
	}
	result += fmt.Sprintf(format2, r.Port, r.SupportsTLS(), startTLS, protocols)
	for _, p := range r.SupportedProtocols {
		ciphers := r.CipherSuiteByProtocol[p]
		if r.HasCipherPreferenceOrderByProtocol[p] {
			ciphers = r.CipherPreferenceOrderByProtocol[p]
		}
		for _, c := range ciphers {
			result += fmt.Sprintf(format3, tlsmodel.TLSVersionMap[p], "", tlsmodel.CipherSuiteMap[c])
		}
	}
	return
}

type sorter []tlsmodel.ScanResult

func (k sorter) Len() int {
	return len(k)
}

func (k sorter) Swap(i, j int) {
	k[i], k[j] = k[j], k[i]
}
func (k sorter) Less(i, j int) bool {
	iPort, _ := strconv.Atoi(k[i].Port)
	jPort, _ := strconv.Atoi(k[j].Port)
	return k[i].Server < k[j].Server || (k[i].Server == k[j].Server && iPort <= jPort)
}

// func main() {

// 	// tls.Client()
// 	// httptrace.ClientTrace().TLSHandshakeStart()
// 	// host := "195.130.217.190"

// 	// host := "eportal.oauife.edu.ng"
// 	// host := "bbc.co.uk"
// 	// host := "mimecast.com"
// 	host := "api.mimecast.com"
// 	// host := "mail.google.com"
// 	// host := "google.com"
// 	// host := "eu-smtp-inbound-1.mimecast.com"
// 	// host := "8.8.8.8"
// 	// port := "443"

// 	// for _, add := range addrs {
// 	// 	println(add)
// 	// }

// 	// results := tlsaudit.ScanHosts([]tlsmodel.HostAndPort{
// 	// 	{
// 	// 		Hostname: host,
// 	// 		Port:     port,
// 	// 	},
// 	// })

// 	results := tlsaudit.ScanHostTLS(host)

// 	for result := range results {
// 		fmt.Printf("%s, %s \n===============\n%s\n", result.Server, result.Port, result.String())
// 	}
// }
