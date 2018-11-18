package tlsaudit

import (
	"net/http"
	"strings"

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
