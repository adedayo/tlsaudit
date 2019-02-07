package tlsmodel

import "strconv"

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
