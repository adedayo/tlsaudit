package asciidoc

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/adedayo/tlsaudit/pkg/assets"
	tlsmodel "github.com/adedayo/tlsaudit/pkg/model"
	"github.com/wcharczuk/go-chart"
	"github.com/wcharczuk/go-chart/drawing"
)

var (
	asciidocExec = func() string {
		executable := "asciidoctor-pdf"
		switch runtime.GOOS {
		case "windows":
			return fmt.Sprintf("%s.exe", executable)
		default:
			return executable
		}
	}()

	funcMap = template.FuncMap{
		"generateGradeTable":      generateGradeTable,
		"generateGradeRangeTable": generateGradeRangeTable,
		"generateGradeLegend":     generateGradeLegend,
	}

	rgbaFix  = regexp.MustCompile(`rgba\((\d+,\d+,\d+),1.0\)`)
	redStyle = chart.Style{
		FillColor:   drawing.ColorRed,
		StrokeColor: drawing.ColorRed,
		StrokeWidth: 0,
	}
	amberStyle = chart.Style{
		FillColor:   drawing.ColorFromHex("ffbf00"), //Amber
		StrokeColor: drawing.ColorFromHex("ffbf00"),
		StrokeWidth: 0,
	}
	greenStyle = chart.Style{
		FillColor:   drawing.ColorFromHex("008000"), //green
		StrokeColor: drawing.ColorFromHex("008000"),
		StrokeWidth: 0,
	}
	blueStyle = chart.Style{
		FillColor:   drawing.ColorBlue,
		StrokeColor: drawing.ColorBlue,
		StrokeWidth: 0,
	}
)

func makeAdvisory(example tlsmodel.GradeExample) []string {
	advisories := []string{}
	switch grade := example.Grade; {
	case grade == "U":
		advisories = append(advisories, "*Unprotected* plaintext communication: No TLS found")
	case strings.HasPrefix(grade, "T"):
		advisories = append(advisories, "Certificate Issues: Certificate *Not Trusted*")
	case grade == "F":
		advisories = append(advisories, "Exploitable and/or patchable problems: misconfigured server, insecure protocols, etc.")
	case grade == "C":
		advisories = append(advisories, "Obsolete configuration: uses obsolete crypto with modern clients; potentially bigger configuration problems")
	case grade == "B" || grade == "B+":
		advisories = append(advisories, "Adequate security with modern clients, with older and potentially obsolete crypto used with older clients; potentially smaller configuration problems")
	case grade == "A":
		advisories = append(advisories, "Strong commercial security")
	case grade == "A+":
		advisories = append(advisories, "Exceptional security configuration. Well done!")
	}
	hostName := ""
	if example.HostName != "" {
		hostName = fmt.Sprintf(" with hostname %s", example.HostName)
	}
	advisories = append(advisories,
		fmt.Sprintf("An example is a service running on Port %s and IP Address %s%s", example.Port, example.Server, hostName))

	return advisories
}

//GenerateReport creates a PDF report from the scan result returning the path to the document
func GenerateReport(summary tlsmodel.ScanResultSummary, results []tlsmodel.HumanScanResult, version string) (reportPath string, err error) {
	asciidocPath, err := exec.LookPath(asciidocExec)
	if err != nil {
		return reportPath, fmt.Errorf("%s executable file not found in your $PATH. Install it and ensure that it is in your $PATH", asciidocExec)
	}

	rr := []scanResult{}
	scanGrades, charts := createScanCharts(results)
	if err != nil {
		return reportPath, err
	}
	for i, r := range results {
		rr = append(rr, scanResult{
			HumanScanResult: r,
			Chart:           charts[i],
			Grade:           scanGrades[i],
		})
	}
	model := reportModel{
		TLSAuditVersion:      version,
		Summary:              summary,
		ScanResults:          rr,
		WorstGradeText:       summary.WorstGrade,
		WorstGradeExample:    summary.WorstGradeExample,
		WorstGradeAdvisories: makeAdvisory(summary.WorstGradeExample),
		TimeStamp:            summary.ScanStart.UTC().Format(time.RFC1123),
	}

	bars := []chart.Value{}
	grades := []string{}
	for grade := range summary.GradeToHostPorts {
		grades = append(grades, grade)
	}
	sort.Strings(grades)

	max := 1
	for _, grade := range grades {
		count := len(summary.GradeToHostPorts[grade])
		if count > max {
			max = count
		}
		bars = append(bars, chart.Value{
			Label: grade,
			Value: float64(count),
			Style: styleGrade(grade),
		})
	}

	graph := chart.BarChart{
		Width:  512,
		Height: 512,
		Title:  "Distribution of Grades",
		Background: chart.Style{
			Padding: chart.Box{
				Top: 40,
			},
		},
		YAxis: chart.YAxis{
			Name: "Count",
			Range: &chart.ContinuousRange{
				Max: float64(max),
				Min: 0,
			},
		},
		Bars: bars,
	}

	buffer := bytes.NewBuffer([]byte{})
	err = graph.Render(chart.SVG, buffer)
	if err != nil {
		return reportPath, err
	}

	data, err := generateAssets(summary.WorstGrade, fixSVGColour(buffer.String()))

	if err != nil {
		return "", fmt.Errorf("Problem generating assets: %s", err.Error())
	}
	model.WorstGrade = data.grade
	model.Logo = data.tlsAuditLogo
	model.SALLogo = data.salLogo
	model.Chart = data.charts[0]
	// model.ScanCharts = createScanChart(results)

	t, err := template.New("").Funcs(funcMap).Parse(assets.Report)
	if err != nil {
		return reportPath, err
	}

	var buf bytes.Buffer

	err = t.Execute(&buf, model)
	if err != nil {
		return reportPath, err
	}

	aDoc, err := generateFile(buf.Bytes(), "report*.adoc")
	if err != nil {
		return reportPath, err
	}

	cmd := exec.Command(asciidocPath, aDoc)
	reportPath = strings.Replace(aDoc, ".adoc", ".pdf", -1)
	if out, err := cmd.CombinedOutput(); err != nil {
		return reportPath, fmt.Errorf("%s%s", string(out), err.Error())
	}
	cleanAssets(model, aDoc)
	return
}

func styleGrade(grade string) chart.Style {
	switch grade {
	case "A+", "A":
		return greenStyle
	case "B+", "B", "C":
		return amberStyle
	default:
		return redStyle
	}
}

func styleScore(score int) chart.Style {
	if score >= 90 {
		return greenStyle
	} else if score >= 70 {
		return amberStyle
	}
	return redStyle
}

func createScanCharts(scans []tlsmodel.HumanScanResult) ([]string, []string) {
	charts := []string{}
	grades := []string{}
	files := []string{}
	cleanUp := func() {
		for _, file := range files {
			os.Remove(file)
		}
	}

	for _, s := range scans {
		graph := chart.BarChart{
			Width:  512,
			Height: 512,
			Title:  "Rating Breakdown",
			Background: chart.Style{
				Padding: chart.Box{
					Top: 40,
				},
			},
			YAxis: chart.YAxis{
				Range: &chart.ContinuousRange{
					Max: 100,
					Min: 0,
				},
				ValueFormatter: func(v interface{}) string {
					if x, ok := v.(float64); ok {
						return fmt.Sprintf("%d", int64(x))
					}
					return fmt.Sprintf("%v", v)
				},
			},
			Bars: []chart.Value{
				{Value: float64(s.Score.CertificateScore), Style: styleScore(s.Score.CertificateScore), Label: "Certificate"},
				{Value: float64(s.Score.ProtocolScore), Style: styleScore(s.Score.ProtocolScore), Label: "Protocol Support"},
				{Value: float64(s.Score.KeyExchangeScore), Style: styleScore(s.Score.KeyExchangeScore), Label: "Key Exchange"},
				{Value: float64(s.Score.CipherEncryptionScore), Style: styleScore(s.Score.CipherEncryptionScore), Label: "Cipher Strength"},
			},
		}
		buffer := bytes.NewBuffer([]byte{})
		_ = graph.Render(chart.SVG, buffer)
		c := fixSVGColour(buffer.String())

		chart, err := generateFile([]byte(c), "tlsaudit_chart.*.svg")
		files = append(files, chart)
		charts = append(charts, chart)
		if err != nil {
			cleanUp()
			return grades, charts
		}

		var gradeIcon string
		grade := strings.ToUpper(strings.TrimSpace(s.Score.Grade))
		if len(grade) == 1 {
			gradeIcon = fmt.Sprintf(assets.Grade, colourGrade(grade), grade)
		} else {
			gradeIcon = fmt.Sprintf(assets.Grade2, colourGrade(grade), grade)
		}
		g, err := generateFile([]byte(gradeIcon), "sal_grade.*.svg")
		files = append(files, g)
		grades = append(grades, g)
		if err != nil {
			cleanUp()
			return grades, charts
		}

	}

	return grades, charts
}

func cleanAssets(assets reportModel, aDoc string) {
	os.Remove(assets.Logo)
	os.Remove(assets.SALLogo)
	os.Remove(assets.Chart)
	for _, chart := range assets.ScanResults {
		os.Remove(chart.Chart)
		os.Remove(chart.Grade)
	}
	os.Remove(aDoc)
}

func fixSVGColour(svg string) string {
	return rgbaFix.ReplaceAllString(svg, "rgb($1)")
}

type assetFiles struct {
	tlsAuditLogo, salLogo, grade string
	charts                       []string
}

func generateAssets(grade string, charts ...string) (assetFiles, error) {
	files := []string{}
	cleanUp := func() {
		for _, file := range files {
			os.Remove(file)
		}
	}

	var axs assetFiles
	var gradeIcon string
	grade = strings.ToUpper(strings.TrimSpace(grade))
	if len(grade) == 1 {
		gradeIcon = fmt.Sprintf(assets.Grade, colourGrade(grade), grade)
	} else {
		gradeIcon = fmt.Sprintf(assets.Grade2, colourGrade(grade), grade)
	}
	grade, err := generateFile([]byte(gradeIcon), "sal_grade.*.svg")
	files = append(files, grade)
	if err != nil {
		cleanUp()
		return axs, err
	}
	axs.grade = grade

	logo, err := generateFile([]byte(assets.Logo), "tlsaudit_logo.*.svg")
	files = append(files, logo)
	if err != nil {
		cleanUp()
		return axs, err
	}
	axs.tlsAuditLogo = logo

	logo, err = generateFile([]byte(assets.SALLogo), "sal_logo.*.svg")
	files = append(files, logo)
	if err != nil {
		cleanUp()
		return axs, err
	}
	axs.salLogo = logo

	for _, c := range charts {
		chart, err := generateFile([]byte(c), "tlsaudit_chart.*.svg")
		files = append(files, chart)
		if err != nil {
			cleanUp()
			return axs, err
		}
		axs.charts = append(axs.charts, chart)
	}

	return axs, nil

}

func colourGrade(grade string) string {
	switch grade {
	case "A", "A+":
		return "green"
	case "B", "B+", "C":
		return "gold"
	default:
		return "red"
	}
}

func generateFile(data []byte, nameGlob string) (fileName string, err error) {
	file, err := ioutil.TempFile("", nameGlob)
	if err != nil {
		return
	}

	if _, err = file.Write(data); err != nil {
		file.Close()
		return
	}

	if err = file.Close(); err != nil {
		return
	}

	return file.Name(), nil
}

func generateGradeLegend(gradeToHostPort map[string][]string) (list string) {
	grades := []string{}
	for g := range gradeToHostPort {
		grades = append(grades, g)
	}
	sort.Strings(grades)
	for _, g := range grades {
		list += fmt.Sprintf("| %s | %s | %d \n", g, tlsmodel.InterpretGrade(g), len(gradeToHostPort[g]))
	}
	return
}
func generateGradeTable(gradeToHostPort map[string][]string) (table string) {

	grades := []string{}
	for g := range gradeToHostPort {
		grades = append(grades, g)
	}
	sort.Strings(grades)
	for _, g := range grades {
		hp := gradeToHostPort[g]
		sort.Strings(hp)
		table += fmt.Sprintf("| IP:Port(s) with grade %s | %s\n", g, strings.Join(hp, ", "))
	}
	return
}

func generateGradeRangeTable(t map[string]tlsmodel.GradePair) (table string) {
	hosts := []string{}
	for h := range t {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	for _, h := range hosts {
		pair := t[h]
		table += fmt.Sprintf("| Grade range for %s | *Worst Grade*: %s, *Best Grade*: %s\n", h, pair.Worst, pair.Best)
	}
	return
}
