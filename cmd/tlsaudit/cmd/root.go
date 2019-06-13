// Copyright © 2019 Adedayo Adetoye (aka Dayo)
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/adedayo/cidr"

	tlsaudit "github.com/adedayo/tlsaudit/pkg"
	tlsmodel "github.com/adedayo/tlsaudit/pkg/model"
	"github.com/spf13/cobra"
)

var (
	app        = "tlsaudit"
	appVersion = "0.0.0"
	rootCmd    = &cobra.Command{
		Use:     app,
		Short:   "Audit TLS settings on open ports on servers",
		Example: "tlsaudit 8.8.8.8/32 10.10.10.1/30\ntlsaudit --timeout=10 8.8.8.8:443/32",
		RunE:    runner,
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(version string) {
	appVersion = version
	rootCmd.Version = version
	rootCmd.Long = fmt.Sprintf(`tlsaudit - Audit TLS settings on open ports on servers
	
	Version: %s
	
	Author: Adedayo Adetoye (Dayo) <https://github.com/adedayo>`, version)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var output, input, service string
var jsonOut, protocolsOnly, hideCerts, quiet, cipherMetrics bool
var timeout, rate, api int

func init() {
	rootCmd.Flags().BoolVarP(&jsonOut, "json", "j", false, "generate JSON output")
	rootCmd.Flags().BoolVarP(&protocolsOnly, "protocols-only", "p", false, "only check supported protocols - will not do detailed checks on supported ciphers (default: false)")
	rootCmd.Flags().BoolVarP(&hideCerts, "hide-certs", "c", false, "suppress certificate information in output (default: false)")
	rootCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "control whether to produce a running commentary of progress or stay quiet till the end (default: false)")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "t", 5, "TIMEOUT (in seconds) to adjust how much we are willing to wait for servers to come back with responses. Smaller timeout sacrifices accuracy for speed")
	rootCmd.Flags().IntVarP(&rate, "rate", "r", 1000, "the rate (in packets per second) that we should use to scan for open ports")
	rootCmd.Flags().IntVar(&api, "api", 12345, "run as an API service on the specified port")
	rootCmd.Flags().StringVarP(&output, "output", "o", "tlsaudit.txt", `write results into an output FILE`)
	rootCmd.Flag("output").NoOptDefVal = "tlsaudit.txt"
	rootCmd.Flags().StringVarP(&input, "input", "i", "tlsaudit_input.txt", `read the CIDR range, IPs and domains to scan from an input FILE separated by commas, or newlines`)
	rootCmd.Flag("input").NoOptDefVal = "tlsaudit_input.txt"
	rootCmd.Flags().StringVarP(&service, "service", "s", tlsaudit.TLSAuditConfigPath, fmt.Sprintf("run %s as a service", app))
	rootCmd.Flag("service").NoOptDefVal = tlsaudit.TLSAuditConfigPath
	rootCmd.Flags().BoolVarP(&cipherMetrics, "show-cipher-metrics", "m", false, "enumerate all ciphers and show associated security and performance metrics (default: false)")
}

func runner(cmd *cobra.Command, args []string) error {
	// if true {
	// 	conf, _ := tlsmodel.GetCipherConfig(0xc019)
	// 	fmt.Printf("%#v", conf)
	// 	return nil
	// }

	if cmd.Flag("show-cipher-metrics").Changed {
		println("Showing cipher metrics")
		showCipherMetrics()
		return nil
	}
	if len(args) == 0 && !cmd.Flag("service").Changed && !cmd.Flag("api").Changed && !cmd.Flag("input").Changed {
		return cmd.Usage()
	}

	if cmd.Flag("service").Changed { // run as a scheduled service with API
		tlsaudit.Service(service)
		return nil
	}

	if cmd.Flag("api").Changed { // run as simple API service
		tlsaudit.ServeAPI(api)
		return nil
	}

	if cmd.Flag("input").Changed {
		args = getCIDRFromFile(input)
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
	fmt.Printf("Starting TLSAudit %s (https://github.com/adedayo/tlsaudit)\nScanning: %s\n", appVersion, strings.Join(args, ", "))
	config := tlsmodel.ScanConfig{
		ProtocolsOnly:    protocolsOnly,
		Timeout:          timeout,
		PacketsPerSecond: rate,
		HideCerts:        hideCerts,
		Quiet:            quiet,
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
	sort.Sort(tlsmodel.ScanResultSorter(scanResults))
	if jsonOut {
		outputJSON(scanResults)
	} else {
		outputText(scanResults, config, cmd)
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
	out := []tlsmodel.HumanScanResult{}
	for _, p := range ports {
		out = append(out, p.ToStringStruct())
	}
	if jsonData, err := json.Marshal(out); err == nil {
		fmt.Printf("%s\n", string(jsonData))
	}

}

func outputText(results []tlsmodel.ScanResult, config tlsmodel.ScanConfig, cmd *cobra.Command) {
	result := "TLS Audit Results\n"
	currentServer := ""
	for _, r := range results {
		outResult, curServer := generateResultText(r, currentServer)
		result += outResult
		currentServer = curServer
	}
	textCSV := strings.Replace(strings.Replace(result, ",", ";", -1), "|", ",", -1)

	for _, scan := range results {
		fmt.Printf("%s\n", scan.ToString(config))
	}

	if cmd.Flag("output").Changed {
		f, err := os.Create(output)
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

func showCipherMetrics() {
	metrics := tlsmodel.EnumerateCipherMetrics()
	fmt.Printf("| %-15s | %-18s | %-16s | %-15s | %-50s |\n", "Preference Index", "Cipher ID", "Security Score", "Performance Cost", "Cipher Suite")
	for index, metric := range metrics {
		fmt.Printf("| %-16d | 0x%04x %11s | %2d %13s | %-16d | %-50s |\n", index+1, metric.CipherConfig.CipherID, "", metric.OverallScore, "", metric.Performance, metric.CipherConfig.Cipher)
	}
}
