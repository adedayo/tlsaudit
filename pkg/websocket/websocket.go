package tlsaudit

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/adedayo/cidr"

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

				scan := make(map[string]tlsmodel.ScanResult)
				totalIPs, processedIPs := 0, 0
				for _, x := range request.CIDRs {
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
				for _, host := range request.CIDRs {
					start := time.Now()
					results := []<-chan tlsmodel.ScanResult{}
					results = append(results, tlsaudit.ScanCIDRTLS(host, request.Config))
					processedIPs += len(cidr.Expand(host))
					for result := range tlsaudit.MergeResultChannels(results...) {
						key := result.Server + result.Port
						if _, present := scan[key]; !present {
							scan[key] = result
							out := tlsmodel.ScanProgress{
								Progress:    100 * float32(processedIPs) / float32(totalIPs),
								ScanResults: []tlsmodel.HumanScanResult{result.ToStringStruct()},
								Narrative: fmt.Sprintf("Finished scan of %s. Progress %f%% %d hosts of a total of %d in %f seconds\n",
									host, 100*float32(processedIPs)/float32(totalIPs), processedIPs, totalIPs, time.Since(start).Seconds()),
							}
							conn.WriteJSON(out)
						}
					}
				}
				var scanResults []tlsmodel.ScanResult
				for k := range scan {
					scanResults = append(scanResults, scan[k])
				}
				for result := range tlsaudit.ScanCIDRTLS(strings.Join(request.CIDRs, " "), request.Config) {
					conn.WriteJSON(result)
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
