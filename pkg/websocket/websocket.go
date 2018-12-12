package websocket

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
	"path/filepath"

	"github.com/adedayo/cidr"
	"github.com/dgraph-io/badger"

	"github.com/adedayo/tlsaudit/pkg"
	"github.com/adedayo/tlsaudit/pkg/model"

	"github.com/gorilla/websocket"
)

var (
	allowedOrigins = []string{
		"auditmate.local:12345",
	}

	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			for _, origin := range allowedOrigins {
				if origin == r.Host {
					return true
				}
			}
			return false
		},
	}
	// dbCatalogueDirectory = "data/tlsaudit/catalogue"
	dayFormat           = "2006-01-02"
	baseScanDBDirectory =  filepath.FromSlash("data/tlsaudit/scan")
	// scanDbDirectory     = filepath.Join(baseScanDBDirectory, time.Now().Format(dayFormat)) 
)

type mydata struct {
	Name string
	Data []byte
}

//RealtimeScan runs a scan asynchronously and streams result over a websocket
func RealtimeScan(w http.ResponseWriter, req *http.Request) {
	if conn, err := upgrader.Upgrade(w, req, nil); err == nil {
		go func() {
			var request tlsmodel.ScanRequest
			if err := conn.ReadJSON(&request); err == nil {

				hosts := []string{}
				psr := tlsmodel.PersistedScanRequest{}
				if request.ScanID == "" { //start a fresh scan
					request.ScanID = GetNextScanID()
					for _, x := range request.CIDRs {
						rng := "/32"
						ports := ""
						if strings.Contains(x, "/") {
							rng = "/" + strings.Split(x, "/")[1]
						}
						if strings.Contains(x, ":") {
							ports = strings.Split(strings.Split(x, "/")[0], ":")[1]
							x = strings.Split(x, ":")[0] + rng

						} else {
							x = strings.Split(x, "/")[0] + rng
						}
						hs := cidr.Expand(x)
						if ports != "" {
							for i, h := range hs {
								hh := strings.Split(h, "/")
								hs[i] = fmt.Sprintf("%s:%s/%s", hh[0], ports, hh[1])
							}
						}
						hosts = append(hosts, hs...)
					}
					//shuffle hosts randomly
					rand.Shuffle(len(hosts), func(i, j int) {
						hosts[i], hosts[j] = hosts[j], hosts[i]
					})
					psr.Hosts = hosts
					psr.ScanStart = time.Now()
					request.Day = psr.ScanStart.Format(dayFormat)
					psr.Request = request
					PersistScanRequest(psr)
				} else {
					//resume an 
					//LoadScanRequest retrieves persisted scan request from folder following a layout patternexisting scan
					psr, err = LoadScanRequest(request.Day,request.ScanID)
					if err != nil {
						return
					}
				}
				scanID := psr.Request.ScanID

				//callback function to stream results over a websocket
				callback := func(position int, results []tlsmodel.ScanResult, narrative string) {
					// persistScans(fmt.Sprintf("%s;%s:%s", scanID, result.Server, result.Port), result)
					res := []tlsmodel.HumanScanResult{}
					for _, r := range results {
						res = append(res, r.ToStringStruct())
					}
					out := tlsmodel.ScanProgress{
						ScanID:      scanID,
						Progress:    100 * float32(position) / float32(len(psr.Hosts)),
						ScanResults: res,
						Narrative:   narrative,
					}
					conn.WriteJSON(out)
				}

				streamExistingResult(psr,callback)
				for index, host := range psr.Hosts {
					if index < psr.Progress {
						continue
					}
					position := index + 1
					scan := make(map[string]tlsmodel.ScanResult)
					results := []<-chan tlsmodel.ScanResult{}
					results = append(results, tlsaudit.ScanCIDRTLS(host, request.Config))
					for result := range tlsaudit.MergeResultChannels(results...) {
						key := result.Server + result.Port
						if _, present := scan[key]; !present {
							scan[key] = result
							narrative := fmt.Sprintf("Partial scan of %s. Progress %f%% %d hosts of a total of %d in %f seconds\n",
								result.Server, 100*float32(position)/float32(len(psr.Hosts)), position, len(psr.Hosts), time.Since(psr.ScanStart).Seconds())
							callback(position, []tlsmodel.ScanResult{result}, narrative)
						}
					}
					psr.Progress = position
					psr.ScanEnd = time.Now()
					PersistScanRequest(psr)
					var scanResults []tlsmodel.ScanResult
					for k := range scan {
						scanResults = append(scanResults, scan[k])
					}
					sort.Sort(tlsmodel.ScanResultSorter(scanResults))
					PersistScans(psr, host, scanResults)
					narrative := fmt.Sprintf("Finished scan of %s. Progress %f%% %d hosts of a total of %d in %f seconds\n",
						host, 100*float32(position)/float32(len(psr.Hosts)), position, len(psr.Hosts), psr.ScanEnd.Sub(psr.ScanStart).Seconds())
					callback(position, scanResults, narrative)

				}
			} else {
				println(err.Error())
				return
			}
		}()
	} else {
		println(err.Error())
		return
	}
}

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
			//LoadScanRequest retrieves persisted scan request from folder following a layout patternme()
			if psr, err := LoadScanRequest(d,scanID); err == nil {
				result = append(result,psr.Request) 
			}
		}
	}
	

	return
}

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