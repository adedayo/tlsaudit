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
	ScanResults          []tlsmodel.HumanScanResult
	ScanCharts           []string
	TimeStamp            string
}
