package main

import (
	"net"
	"sync"

	"github.com/adedayo/cidr"
	tlsaudit "github.com/adedayo/tlsaudit/pkg"
	tlsmodel "github.com/adedayo/tlsaudit/pkg/model"
)

var (
	resolvedIPs = make(map[string]string)
	lock        = sync.RWMutex{}
)

func main() {
	suspend := make(chan bool)
	println("Running TLSAudit Service ...")
	ips := ipSource()
	go resolveIPs(ips)
	tlsaudit.ScheduleTLSAudit(ips, ipResolver)
	<-suspend
}

func resolveIPs(ips []string) {
	for _, ip := range ips {
		lock.Lock()
		if _, present := resolvedIPs[ip]; !present {
			if hosts, err := net.LookupAddr(ip); err == nil && len(hosts) > 0 {
				resolvedIPs[ip] = hosts[0]
				ips = append(ips, ip)
			} else {
				resolvedIPs[ip] = ""
			}
		}
		lock.Unlock()
	}
}

func ipResolver(ip string) string {
	defer lock.Unlock()
	lock.Lock()
	if hostname, present := resolvedIPs[ip]; present {
		return hostname
	}
	return ""
}

func ipSource() []string {
	config := tlsaudit.LoadTLSAuditConfig()
	return getIPsToScan(config)
}

func getIPsToScan(config tlsmodel.TLSAuditConfig) []string {
	data := make(map[string]bool)
	ips := []string{}
	for _, c := range config.CIDRRanges {
		println(c)
		for _, ip := range cidr.Expand(c) {
			println(ip)
			if _, present := data[ip]; !present {
				if hosts, err := net.LookupAddr(ip); err == nil && len(hosts) > 0 {
					data[ip] = true
					ips = append(ips, ip)
				}
			}
		}
	}
	return ips
}
