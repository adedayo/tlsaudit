package tlsaudit

import (
	"fmt"
	"math/rand"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/adedayo/cidr"

	tlsmodel "github.com/adedayo/tlsaudit/pkg/model"

	"github.com/gorilla/websocket"
)

var (
	allowedOrigins = []string{
		"localhost:12345",
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
)

type mydata struct {
	Name string
	Data []byte
}

//RealtimeScan runs a scan asynchronously and streams result over a websocket
func RealtimeScan(w http.ResponseWriter, req *http.Request) {
	if conn, err := upgrader.Upgrade(w, req, nil); err == nil {
		go func() {
			defer conn.Close()
			var request tlsmodel.ScanRequest
			if err := conn.ReadJSON(&request); err == nil {
				hosts := []string{}
				psr := tlsmodel.PersistedScanRequest{}
				if request.ScanID == "" { //start a fresh scan
					request.ScanID = GetNextScanID()
					for _, x := range request.CIDRs {
						x = strings.ReplaceAll(x, ",", "")
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
								hs[i] = fmt.Sprintf("%s:%s/32", h, ports)
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
					//resume an existing scan
					psr, err = LoadScanRequest(request.Day, request.ScanID)
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

				streamExistingResult(psr, callback)
				for index, host := range psr.Hosts {
					if index < psr.Progress {
						continue
					}
					position := index + 1
					scan := make(map[string]tlsmodel.ScanResult)
					results := []<-chan tlsmodel.ScanResult{}
					results = append(results, ScanCIDRTLS(host, request.Config))
					for result := range MergeResultChannels(results...) {
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
