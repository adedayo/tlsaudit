package tlsmodel

import (
	"fmt"
	"strconv"
	"strings"
)

//ScanResultSorter sorts scan results by server IP and port
type ScanResultSorter []ScanResult

func (k ScanResultSorter) Len() int {
	return len(k)
}

func (k ScanResultSorter) Swap(i, j int) {
	k[i], k[j] = k[j], k[i]
}
func (k ScanResultSorter) Less(i, j int) bool {
	iPort, _ := strconv.Atoi(k[i].Port)
	jPort, _ := strconv.Atoi(k[j].Port)
	return k[i].Server < k[j].Server || (k[i].Server == k[j].Server && iPort <= jPort)
}

//CipherMetricsSorter sorts scan results by server IP and port
type CipherMetricsSorter []CipherMetrics

func (k CipherMetricsSorter) Len() int {
	return len(k)
}

func (k CipherMetricsSorter) Swap(i, j int) {
	k[i], k[j] = k[j], k[i]
}
func (k CipherMetricsSorter) Less(i, j int) bool {
	return k[i].OverallScore > k[j].OverallScore || (k[i].OverallScore == k[j].OverallScore && k[i].Performance <= k[j].Performance)
}

//GradePair collects the best and worst grade of a server scan
type GradePair struct {
	Best, Worst string
}

//GetBasicScanSummary basic scan summary
func GetBasicScanSummary(results []HumanScanResult) BasicScanSummary {
	best := "Best"
	worst := "Worst"
	worstExample := ""
	bestExample := ""
	hostGrades := make(map[string]GradePair)
	gradeToPorts := make(map[string][]string)
	for _, r := range results {
		grade := r.Score.Grade
		if r.Score.OrderGrade(best) < r.Score.OrderGrade(grade) { //better grade
			best = grade
			bestExample = fmt.Sprintf("%s:%s:%s", r.Server, r.Port, r.HostName)
		}
		if r.Score.OrderGrade(worst) > r.Score.OrderGrade(grade) { //worse grade
			worst = grade
			worstExample = fmt.Sprintf("%s:%s:%s", r.Server, r.Port, r.HostName)
		}

		if hostPorts, present := gradeToPorts[grade]; present {
			hostPorts = append(hostPorts, fmt.Sprintf("%s:%s", r.Server, r.Port))
			gradeToPorts[grade] = hostPorts
		} else {
			gradeToPorts[grade] = []string{fmt.Sprintf("%s:%s", r.Server, r.Port)}
		}

		if gp, ok := hostGrades[r.Server]; ok {
			if gp.Best == "" || r.Score.OrderGrade(gp.Best) < r.Score.OrderGrade(grade) { // better grade
				gp.Best = grade
			}

			if gp.Worst == "" || r.Score.OrderGrade(gp.Worst) > r.Score.OrderGrade(grade) { //worse grade
				gp.Worst = grade
			}
			hostGrades[r.Server] = gp
		} else {
			hostGrades[r.Server] = GradePair{grade, grade}
		}

	}

	return BasicScanSummary{
		HostCount:         len(hostGrades),
		BestGrade:         best,
		BestGradeExample:  makeExample(best, bestExample),
		WorstGradeExample: makeExample(worst, worstExample),
		WorstGrade:        worst,
		GradeToHostPorts:  gradeToPorts,
		HostGrades:        hostGrades,
		PortCount:         len(results),
	}
}

func makeExample(grade, example string) GradeExample {
	ex := strings.Split(example, ":")
	return GradeExample{
		Grade:    grade,
		Server:   ex[0],
		Port:     ex[1],
		HostName: ex[2],
	}
}

//InterpretGrade is a mapping from grade to explanatory text
func InterpretGrade(grade string) string {

	switch grade := grade; {
	case grade == "U":
		return "Unprotected plaintext communication: No TLS found"
	case strings.HasPrefix(grade, "T"):
		return "Certificate Issues: Certificate Not Trusted"
	case grade == "F":
		return "Exploitable and/or patchable problems: misconfigured server, insecure protocols, etc."
	case grade == "C":
		return "Obsolete configuration: uses obsolete crypto with modern clients; potentially bigger configuration problems"
	case grade == "B" || grade == "B+":
		return "Adequate security with modern clients, with older and potentially obsolete crypto used with older clients; potentially smaller configuration problems"
	case grade == "A":
		return "Strong commercial security"
	case grade == "A+":
		return "Exceptional security configuration. Well done!"
	case grade == "D":
		return "Configuration with security issues that are typically difficult or unlikely to be exploited, but can and should be addressed"
	default:
		return "Unused grade"
	}
}

//GetUniqueCertificates returns all the unique certificates (using the certificate serial number) from a scan result
func GetUniqueCertificates(scan HumanScanResult) (certs []HumanCertificate) {
	ids := make(map[string]bool)
	for _, cp := range scan.CertificatesPerProtocol {
		for _, cert := range cp {
			if _, present := ids[cert.SerialNumber]; !present {
				certs = append(certs, cert)
				ids[cert.SerialNumber] = true
			}
		}
	}
	return
}
