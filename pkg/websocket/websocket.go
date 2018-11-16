package tlsaudit

import (
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

//RealtimeScan runs a scan asynchronously and streams result over a websocket
func RealtimeScan(w http.ResponseWriter, req *http.Request) {
	if conn, err := upgrader.Upgrade(w, req, nil); err == nil {
		defer conn.Close()
		go func() {
			if msgType, msg, err := conn.ReadMessage(); err == nil {
				println(msgType, msg)
			}
		}()
	} else {
		println(err.Error())
		return
	}
}
