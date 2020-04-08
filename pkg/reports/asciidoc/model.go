package asciidoc

import tlsmodel "github.com/adedayo/tlsaudit/pkg/model"

type reportModel struct {
	TLSAuditVersion      string
	Logo                 string
	SALLogo              string
	WorstGrade           string
	WorstGradeText       string
	WorstGradeExample    tlsmodel.GradeExample
	WorstGradeAdvisories []string
	Chart                string
	Summary              tlsmodel.ScanResultSummary
	ScanResults          []scanResult
	// ScanCharts           []string
	TimeStamp string
}

type scanResult struct {
	tlsmodel.HumanScanResult
	Chart string
	Grade string
}
