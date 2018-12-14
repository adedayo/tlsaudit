package tlsaudit

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/adedayo/tlsaudit/pkg/model"
	"github.com/dgraph-io/badger"
)

var (
	dayFormat           = "2006-01-02"
	baseScanDBDirectory = filepath.FromSlash("data/tlsaudit/scan")
)

//ListScans returns the ScanID list of persisted scans
func ListScans(rewindDays int) (result []tlsmodel.ScanRequest) {
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
			if psr, err := LoadScanRequest(d, scanID); err == nil {
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
	opts := badger.DefaultOptions
	opts.Dir = filepath.Join(baseScanDBDirectory, psr.Request.Day, psr.Request.ScanID)
	opts.ValueDir = filepath.Join(baseScanDBDirectory, psr.Request.Day, psr.Request.ScanID)
	db, err := badger.Open(opts)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer db.Close()

	hostResults := make(map[string][]tlsmodel.ScanResult)
	total := len(psr.Hosts)
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
	opts := badger.DefaultOptions
	opts.Dir = filepath.Join(baseScanDBDirectory, psr.Request.Day, psr.Request.ScanID)
	opts.ValueDir = filepath.Join(baseScanDBDirectory, psr.Request.Day, psr.Request.ScanID)
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

//LoadScanRequest retrieves persisted scan request from folder following a layout pattern
func LoadScanRequest(dir, scanID string) (psr tlsmodel.PersistedScanRequest, e error) {
	opts := badger.DefaultOptions
	opts.Dir = filepath.Join(baseScanDBDirectory, dir, scanID, "request")
	opts.ValueDir = filepath.Join(baseScanDBDirectory, dir, scanID, "request")
	db, err := badger.Open(opts)
	if err != nil {
		log.Fatal(err)
		return
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
	return tlsmodel.UnmasharlPersistedScanRequest(data)
}

//arshallScanResults marshalls scan results
func marshallScanResults(s []tlsmodel.ScanResult) []byte {
	result := bytes.Buffer{}
	gob.Register([]tlsmodel.ScanResult{})
	err := gob.NewEncoder(&result).Encode(&s)
	if err != nil {
		log.Print(err)
	}
	return result.Bytes()
}

//PersistScanRequest persists scan requesr
func PersistScanRequest(psr tlsmodel.PersistedScanRequest) {
	opts := badger.DefaultOptions
	opts.Dir = filepath.Join(baseScanDBDirectory, psr.Request.Day, psr.Request.ScanID, "request")
	opts.ValueDir = filepath.Join(baseScanDBDirectory, psr.Request.Day, psr.Request.ScanID, "request")
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

	if psr.Progress%10 == 0 { //compact DB every 10 run
		lsmx, vlogx := db.Size()
		for db.RunValueLogGC(.8) == nil {
			lsmy, vlogy := db.Size()
			println("Compacted DB")
			fmt.Printf("Before LSM: %d, VLOG: %d, After LSM: %d, VLOG: %d\n", lsmx, vlogx, lsmy, vlogy)
			lsmx, vlogx = lsmy, vlogy
		}
	}
}

//CompactDB reclaims space by pruning the database
func CompactDB(dayPath, scanID string) {

	//compact the scan requests
	opts := badger.DefaultOptions
	opts.Dir = filepath.Join(baseScanDBDirectory, dayPath, scanID, "request")
	opts.ValueDir = filepath.Join(baseScanDBDirectory, dayPath, scanID, "request")
	opts.NumVersionsToKeep = 0
	db, err := badger.Open(opts)
	if err != nil {
		println(err.Error())
		log.Fatal(err)
		return
	}
	lsmx, vlogx := db.Size()
	for db.RunValueLogGC(.8) == nil {
		lsmy, vlogy := db.Size()
		println("Compacted DB", opts.Dir)
		fmt.Printf("Before LSM: %d, VLOG: %d, After LSM: %d, VLOG: %d\n", lsmx, vlogx, lsmy, vlogy)
		lsmx, vlogx = lsmy, vlogy
	}
	db.Close()

	//compact the scan results
	opts.Dir = filepath.Join(baseScanDBDirectory, dayPath, scanID)
	opts.ValueDir = filepath.Join(baseScanDBDirectory, dayPath, scanID)
	db, err = badger.Open(opts)
	if err != nil {
		println(err.Error())

		log.Fatal(err)
		return
	}
	lsmx, vlogx = db.Size()
	for db.RunValueLogGC(.8) == nil {
		lsmy, vlogy := db.Size()
		println("Compacted DB", opts.Dir)
		fmt.Printf("Before LSM: %d, VLOG: %d, After LSM: %d, VLOG: %d\n", lsmx, vlogx, lsmy, vlogy)
		lsmx, vlogx = lsmy, vlogy
	}
	db.Close()

}

//GetNextScanID returns the next unique scan ID
func GetNextScanID() string {
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
