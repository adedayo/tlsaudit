package tlsaudit

import (
	"bytes"
	"crypto/rsa"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mitchellh/go-homedir"

	tlsmodel "github.com/adedayo/tlsaudit/pkg/model"
	"github.com/dgraph-io/badger"
)

var (
	dayFormat              = "2006-01-02"
	baseDirectory          = ""
	baseScanDBDirectory    = filepath.Join(baseDirectory, filepath.FromSlash("data/tlsaudit/scan"))
	scanSummaryCache       = make(map[string]tlsmodel.ScanResultSummary)
	scanCache              = make(map[string]tlsmodel.ScanData)
	psrCache               = make(map[string]tlsmodel.PersistedScanRequest)
	latestTLSAuditSnapshot = make(map[time.Time]tlsmodel.TLSAuditSnapshotHuman)
	lock                   = sync.RWMutex{}
	scanCacheLock          = sync.RWMutex{}
	myLogger               = logger{}
)

type logger struct {
}

func (log logger) Errorf(format string, params ...interface{}) {
	fmt.Printf(format, params...)
}

func (log logger) Warningf(format string, params ...interface{}) {
	fmt.Printf(format, params...)

}
func (log logger) Infof(format string, params ...interface{}) {
}

func (log logger) Debugf(format string, params ...interface{}) {
}

func init() {
	if dir, err := homedir.Expand("~/.tlsaudit"); err == nil {
		baseDirectory = dir
		baseScanDBDirectory = filepath.Join(baseDirectory, filepath.FromSlash("data/tlsaudit/scan"))
		if _, err := os.Stat(baseScanDBDirectory); os.IsNotExist(err) {
			if err2 := os.MkdirAll(baseScanDBDirectory, 0755); err2 != nil {
				fmt.Printf("Could not create the path %s\n", baseScanDBDirectory)
			}
		}
	}
}

//GetScanData returns the scan results of a given scan
func GetScanData(date, scanID string) tlsmodel.ScanData {
	scanCacheLock.Lock()
	key := fmt.Sprintf("%s:%s", date, scanID)
	if cache, ok := scanCache[key]; ok {
		scanCacheLock.Unlock()
		return cache
	}
	scanCacheLock.Unlock()
	getScanSummary(date, scanID) //side effect populate cache
	return GetScanData(date, scanID)
}

//ListScans returns the ScanID list of  persisted scans
func ListScans(rewindDays int, completed bool) (result []tlsmodel.AdvancedScanRequest) {
	if rewindDays < 0 {
		log.Print("The number of days in the past must be non-negative.")
		return
	}
	dirs, err := ioutil.ReadDir(baseScanDBDirectory)
	if err != nil {
		log.Print(err)
		return
	}

	allowedDates := make(map[string]bool)
	today := time.Now()
	for d := rewindDays; d >= 0; d-- {
		allowedDates[fmt.Sprintf("%s", today.AddDate(0, 0, -1*d).Format(dayFormat))] = true
	}

	matchedDirs := []string{}
	for _, d := range dirs {
		dirName := d.Name()
		if _, present := allowedDates[dirName]; present {
			matchedDirs = append(matchedDirs, dirName)
		}
	}

	for _, d := range matchedDirs {
		dirs, err := ioutil.ReadDir(filepath.Join(baseScanDBDirectory, d))
		if err != nil {
			log.Print(err)
			return
		}

		for _, sID := range dirs {
			scanID := sID.Name()
			//LoadScanRequest retrieves persisted scan request from folder following a layout pattern
			if psr, err := LoadScanRequest(d, scanID); err == nil && (psr.HostCount == psr.Progress) == completed {
				result = append(result, psr.Request)
			}
		}
	}
	return
}

//StreamScan streams the result to a callback function
func StreamScan(day, scanID string, callback func(progress, total int, results []tlsmodel.HumanScanResult)) {
	if psr, err := LoadScanRequest(day, scanID); err == nil {
		tot := psr.Progress
		streamExistingResult(psr, func(progress int, results []tlsmodel.ScanResult, narrative string) {
			callback(progress, tot, humanise(results))
		})
	}
}

func humanise(in []tlsmodel.ScanResult) (out []tlsmodel.HumanScanResult) {
	for _, r := range in {
		out = append(out, r.ToStringStruct())
	}
	return
}

//StreamExistingResult sends data via a callback function
func streamExistingResult(psr tlsmodel.PersistedScanRequest,
	callback func(progress int, result []tlsmodel.ScanResult, narrative string)) {
	dbDir := filepath.Join(baseScanDBDirectory, psr.Request.Day, psr.Request.ScanID)
	opts := badger.DefaultOptions(dbDir)
	opts.Logger = myLogger
	opts.ReadOnly = true
	db, err := badger.Open(opts)
	if err != nil {
		log.Print(err)
		return
	}
	defer db.Close()

	hostResults := make(map[string][]tlsmodel.ScanResult)
	total := 0
	for _, gs := range psr.GroupedHosts {
		total += len(gs.Hosts)
	}

	position := 0

	db.View(func(txn *badger.Txn) error {

		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 100
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			host := string(item.Key())
			if _, present := hostResults[host]; !present {
				res, err := item.ValueCopy(nil)
				if err != nil {
					return err
				}
				result, err := tlsmodel.UnmarsharlScanResult(res)
				if err != nil {
					return err
				}
				position++
				narrative := fmt.Sprintf("Finished scan of %s. Progress %f%% %d hosts of a total of %d in %f seconds\n",
					host, 100*float32(position)/float32(total), position, total, time.Since(psr.ScanStart).Seconds())
				callback(position, result, narrative)
			}
		}
		return nil
	})

}

//PersistScans persists the result of scans per server
func PersistScans(psr tlsmodel.PersistedScanRequest, server string, scans []tlsmodel.ScanResult) {
	dbDir := filepath.Join(baseScanDBDirectory, psr.Request.Day, psr.Request.ScanID)
	opts := badger.DefaultOptions(dbDir)
	opts.Logger = myLogger
	opts.NumVersionsToKeep = 0
	db, err := badger.Open(opts)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer db.Close()

	db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(server), marshallScanResults(scans))
	})
}

//GetScanSummaries returns summaries of scans in the last number of days indicated by rewindDays
func GetScanSummaries(rewindDays int) []tlsmodel.ScanResultSummary {
	summaries := []tlsmodel.ScanResultSummary{}
	for _, scan := range ListScans(rewindDays, true) {
		summaries = append(summaries, getScanSummary(scan.Day, scan.ScanID))
	}
	return summaries
}

type gradePair struct {
	best, worst string
}

//getScanSummary computes a summary of a scan as indicated by a scan date and ID
func getScanSummary(dateDir, scanID string) tlsmodel.ScanResultSummary {
	lock.Lock()
	if sum, ok := scanSummaryCache[fmt.Sprintf("%s:%s", dateDir, scanID)]; ok {
		lock.Unlock()
		return sum
	}
	lock.Unlock()
	summary := tlsmodel.ScanResultSummary{}
	summary.HostGrades = make(map[string]string)
	summary.WorstGrade = "Worst"
	summary.BestGrade = "Best"
	hosts := make(map[string]gradePair) // map from host to the best and worst grades
	gradeToPorts := make(map[string][]string)
	key := fmt.Sprintf("%s:%s", dateDir, scanID)
	scanCacheLock.Lock()
	defer scanCacheLock.Unlock()
	StreamScan(dateDir, scanID, func(progress, total int, results []tlsmodel.HumanScanResult) {
		summary.Progress = progress
		summary.HostCount = total

		for _, r := range results {
			if scanData, ok := scanCache[key]; ok {
				gid := r.GroupID
				if groupResults, present := scanData.Results[gid]; present {
					groupResults = append(groupResults, r)
					scanData.Results[gid] = groupResults
				} else {
					scanData.Results[gid] = []tlsmodel.HumanScanResult{r}
				}
				scanCache[key] = scanData
			} else {
				data := make(map[int][]tlsmodel.HumanScanResult)
				data[r.GroupID] = []tlsmodel.HumanScanResult{r}
				scanCache[key] = tlsmodel.ScanData{
					Results: data,
				}
			}
			summary.PortCount++
			grade := r.Score.Grade
			if hostPorts, present := gradeToPorts[grade]; present {
				hostPorts = append(hostPorts, fmt.Sprintf("%s:%s", r.Server, r.Port))
				gradeToPorts[grade] = hostPorts
			} else {
				gradeToPorts[grade] = []string{fmt.Sprintf("%s:%s", r.Server, r.Port)}
			}

			if g, ok := hosts[r.Server]; ok {
				if g.best == "" || r.Score.OrderGrade(g.best) < r.Score.OrderGrade(grade) { // better grade
					g.best = grade
				}

				if g.worst == "" || r.Score.OrderGrade(g.worst) > r.Score.OrderGrade(grade) { //worse grade
					g.worst = grade
				}
				hosts[r.Server] = g
			} else {
				hosts[r.Server] = gradePair{grade, grade}
			}

			if r.Score.OrderGrade(summary.BestGrade) < r.Score.OrderGrade(grade) {
				summary.BestGrade = grade
			}

			if r.Score.OrderGrade(summary.WorstGrade) > r.Score.OrderGrade(grade) {
				summary.WorstGrade = grade
			}
		}
	})

	for host, grades := range hosts {
		summary.HostGrades[host] = fmt.Sprintf("%s:%s", grades.worst, grades.best)
	}

	if psr, err := LoadScanRequest(dateDir, scanID); err == nil {
		summary.ScanStart = psr.ScanStart
		summary.ScanEnd = psr.ScanEnd
		summary.Request = psr.Request
		if cache, ok := scanCache[key]; ok {
			cache.ScanRequest = psr.Request
			scanCache[key] = cache
		}
	}
	summary.GradeToHostPorts = gradeToPorts
	lock.Lock()
	scanSummaryCache[fmt.Sprintf("%s:%s", dateDir, scanID)] = summary
	lock.Unlock()

	return summary
}

//LoadScanRequest retrieves persisted scan request from folder following a layout pattern
func LoadScanRequest(dir, scanID string) (psr tlsmodel.PersistedScanRequest, e error) {
	lock.Lock()
	if psr, ok := psrCache[fmt.Sprintf("%s:%s", dir, scanID)]; ok {
		lock.Unlock()
		return psr, nil
	}
	lock.Unlock()
	dbDir := filepath.Join(baseScanDBDirectory, dir, scanID, "request")
	opts := badger.DefaultOptions(dbDir)
	opts.Logger = myLogger
	opts.ReadOnly = true
	db, err := badger.Open(opts)
	if err != nil {
		return psr, err
	}
	defer db.Close()
	data := []byte{}
	outErr := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(scanID))
		if err != nil {
			return err
		}

		data, err = item.ValueCopy(nil)
		if err != nil {
			return err
		}
		return nil
	})
	if outErr != nil {
		return psr, outErr
	}
	psr, e = tlsmodel.UnmasharlPersistedScanRequest(data)
	if e == nil && psr.HostCount == psr.Progress {
		lock.Lock()
		psrCache[fmt.Sprintf("%s:%s", dir, scanID)] = psr
		lock.Unlock()
	}
	return psr, e
}

//arshallScanResults marshalls scan results
func marshallScanResults(s []tlsmodel.ScanResult) []byte {
	result := bytes.Buffer{}
	gob.Register(rsa.PublicKey{}) // there is an indirect reference to it,
	gob.Register([]tlsmodel.ScanResult{})
	err := gob.NewEncoder(&result).Encode(&s)
	if err != nil {
		log.Print(err)
	}
	return result.Bytes()
}

//PersistScanRequest persists scan request
func PersistScanRequest(psr tlsmodel.PersistedScanRequest) {
	dbDir := filepath.Join(baseScanDBDirectory, psr.Request.Day, psr.Request.ScanID, "request")
	opts := badger.DefaultOptions(dbDir)
	opts.Logger = myLogger
	opts.NumVersionsToKeep = 0
	db, err := badger.Open(opts)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer db.Close()

	db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(psr.Request.ScanID), psr.Marshall())
	})
}

//getNextScanID returns the next unique scan ID
func getNextScanID() string {
	prefix := filepath.Join(baseScanDBDirectory, time.Now().Format(dayFormat))
	if _, err := os.Stat(prefix); os.IsNotExist(err) {
		if err2 := os.MkdirAll(prefix, 0755); err2 != nil {
			log.Fatal("Could not create the path ", prefix)
		}
	}
	dir, err := ioutil.TempDir(prefix, "")
	if err != nil {
		log.Fatal(err)
		return ""
	}
	return strings.Replace(strings.TrimPrefix(dir, prefix), string(os.PathSeparator), "", -1)
}
