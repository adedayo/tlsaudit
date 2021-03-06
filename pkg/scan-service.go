package tlsaudit

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/adedayo/cidr"
	"github.com/mitchellh/go-homedir"

	tlsmodel "github.com/adedayo/tlsaudit/pkg/model"
	"github.com/carlescere/scheduler"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
)

var (
	//TLSAuditConfigPath is the default config path of the TLSAudit service
	TLSAuditConfigPath = filepath.Join("data", "config", "TLSAuditConfig.yml")
	//control files
	runFlag     = "runlock.txt"
	runFlag2    = "deletethistoresume.txt"
	workList    = "worklist.txt"
	progress    = "progress.txt"
	resolvedIPs = make(map[string]string)
	ipLock      = sync.RWMutex{}
	routes      = mux.NewRouter()
)

func init() {
	if home, err := homedir.Expand("~/.tlsaudit"); err == nil {
		home = filepath.Join(home, "data", "tlsaudit")
		if _, err := os.Stat(home); os.IsNotExist(err) {
			if err2 := os.MkdirAll(home, 0755); err2 != nil {
				log.Errorln("Could not create the path ", home)
			}
		}
		runFlag = filepath.Join(home, "runlock.txt")
		runFlag2 = filepath.Join(home, "deletethistoresume.txt")
		workList = filepath.Join(home, "worklist.txt")
		progress = filepath.Join(home, "progress.txt")
	}
	AddTLSAuditRoutes(routes)
}

//AddTLSAuditRoutes adds TLSAudit service's routes to an existing router setup
func AddTLSAuditRoutes(r *mux.Router) {
	r.HandleFunc("/scan", RealtimeAdvancedScan).Methods("GET")
	r.HandleFunc("/listtlsscan/{rewind}/{completed}", getTLSAuditScanRequests).Methods("GET")
	r.HandleFunc("/getscandata/{date}/{scanID}", getTLSAuditScanData).Methods("GET")
	r.HandleFunc("/getprotocols/{date}/{scanID}", getTLSProtocols).Methods("GET")
	r.HandleFunc("/getscansummaries/{rewind}", getTLSScanSummaries).Methods("GET")
}

//Service main service entry function
func Service(configPath string) {
	println("Running TLSAudit Service ...")
	TLSAuditConfigPath = configPath
	ScheduleTLSAudit(getIPsFromConfig, ipResolver)
	if config, err := loadTLSConfig(configPath); err == nil {
		ServeAPI(config.ServicePort)
	}
}

//ServeAPI provides an API endpoint for interacting with TLSAudit on the localhost
func ServeAPI(port int) {
	corsOptions := []handlers.CORSOption{
		handlers.AllowedOrigins([]string{"http://localhost:4200",
			fmt.Sprintf("http://localhost:%d", port)}),
		handlers.AllowedMethods([]string{"GET", "HEAD", "POST"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization", "Accept",
			"Accept-Language", "Origin"}),
		handlers.AllowCredentials(),
	}
	log.Error(http.ListenAndServe(fmt.Sprintf(":%d", port), handlers.CORS(corsOptions...)(routes)))
}

//ServeAPITLS provides an API endpoint over TLS for interacting with TLSAudit on the
// localhost potentially for remote consumption
func ServeAPITLS(port int) {
	corsOptions := []handlers.CORSOption{
		handlers.AllowedOrigins([]string{"http://localhost:4200",
			fmt.Sprintf("http://localhost:%d", port)}),
		handlers.AllowedMethods([]string{"GET", "HEAD", "POST"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization", "Accept",
			"Accept-Language", "Origin"}),
		handlers.AllowCredentials(),
	}

	certFile, keyFile, err := genCerts()
	if err == nil {
		log.Error(http.ListenAndServeTLS(fmt.Sprintf(":%d", port), certFile, keyFile, handlers.CORS(corsOptions...)(routes)))
	} else {
		log.Error(err)
	}
}

func getTLSAuditScanRequests(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	rewind := 365
	if rew, err := strconv.Atoi(vars["rewind"]); err == nil {
		rewind = rew
	}
	completed := false
	if comp, err := strconv.ParseBool(vars["completed"]); err == nil {
		completed = comp
	}

	json.NewEncoder(w).Encode(ListScans(rewind, completed))
}

func getTLSAuditScanData(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	date := vars["date"]
	scanID := vars["scanID"]
	json.NewEncoder(w).Encode(GetScanData(date, scanID))
}

func getTLSProtocols(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	date := vars["date"]
	scanID := vars["scanID"]
	type data struct {
		Hostname  string
		Protocols []string
		IP        string
		STARTTLS  bool
		Score     tlsmodel.SecurityScore
	}
	result := []data{}
	for _, ds := range GetScanData(date, scanID).Results {
		for _, d := range ds {
			if d.SupportsTLS {
				result = append(result, data{
					Hostname:  d.HostName,
					Protocols: d.SupportedProtocols,
					IP:        d.Server,
					STARTTLS:  d.IsSTARTTLS,
					Score:     d.Score,
				})
			}
		}
	}

	json.NewEncoder(w).Encode(result)
}

func getTLSScanSummaries(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	rewind := 365
	if rew, err := strconv.Atoi(vars["rewind"]); err == nil {
		rewind = rew
	}
	json.NewEncoder(w).Encode(GetScanSummaries(rewind))
}

func resolveIPs(ips []string) {
	for _, ip := range ips {
		ipLock.Lock()
		if _, present := resolvedIPs[ip]; !present {
			if hosts, err := net.LookupAddr(ip); err == nil && len(hosts) > 0 {
				resolvedIPs[ip] = hosts[0]
				ips = append(ips, ip)
			} else {
				resolvedIPs[ip] = ""
			}
		}
		ipLock.Unlock()
	}
}

func ipResolver(ip string) string {
	defer ipLock.Unlock()
	ipLock.Lock()
	if hostname, present := resolvedIPs[ip]; present {
		return hostname
	}
	return ""
}
func getIPsFromConfig() []tlsmodel.GroupedHost {
	config, err := loadTLSConfig(TLSAuditConfigPath)
	if err != nil {
		return []tlsmodel.GroupedHost{}
	}
	ips := getIPsToScan(config)
	return ips
}

func getIPsToScan(config tlsmodel.TLSAuditConfig) []tlsmodel.GroupedHost {

	groupedHosts := []tlsmodel.GroupedHost{}
	for _, sg := range config.ScanGroups {
		data := make(map[string]string)
		ips := []string{}
		for _, c := range sg.CIDRRanges {
			ports := ""
			if strings.Contains(c, ":") {
				cc, p, err := extractPorts(c)
				if err != nil {
					continue
				}
				c = cc
				ports = p
			}
			for _, ip := range cidr.Expand(c) {
				ip = fmt.Sprintf("%s/32", ip)
				if ps, present := data[ip]; present {
					if ps == "" {
						data[ip] = ports
					} else if ports != "" {
						data[ip] = fmt.Sprintf("%s,%s", ps, ports)
					}
				} else {
					data[ip] = ports
				}
			}
		}
		for ip, ports := range data {
			x := ip
			if ports != "" {
				z := strings.Split(ip, "/")
				if len(z) != 2 {
					continue
				}
				x = fmt.Sprintf("%s:%s/%s", z[0], ports, z[1])
				println(x)
			}
			ips = append(ips, x)
		}
		groupedHosts = append(groupedHosts, tlsmodel.GroupedHost{
			ScanGroup: sg,
			Hosts:     ips,
		})
	}
	return groupedHosts
}

func extractPorts(cidrX string) (string, string, error) {
	cs := strings.Split(cidrX, ":")
	if len(cs) != 2 {
		return cidrX, "", fmt.Errorf("Bad CIDR with port format %s", cidrX)
	}
	ip := cs[0]
	if !strings.Contains(cs[1], "/") {
		return ip + "/32", cs[1], nil
	}
	rng := strings.Split(cs[1], "/")
	if len(rng) != 2 {
		return cidrX, "", fmt.Errorf("Bad CIDR with port format %s", cidrX)
	}
	return fmt.Sprintf("%s/%s", ip, rng[1]), rng[0], nil
}

//ScheduleTLSAudit runs TLSAudit scan
func ScheduleTLSAudit(ipSource func() []tlsmodel.GroupedHost, resolver func(string) string) {

	//a restart schould clear the lock file
	if _, err := os.Stat(runFlag2); !os.IsNotExist(err) { // there is a runlock
		if err := os.Remove(runFlag2); err != nil {
			println(err.Error())
			log.Error(err)
		}
	}

	scanJob := func() {
		runTLSScan(ipSource, resolver)
	}

	if config, err := loadTLSConfig(TLSAuditConfigPath); err == nil {
		for _, t := range config.DailySchedules {
			if config.IsProduction {
				println("Running next at ", t)
				scheduler.Every().Day().At(t).Run(scanJob)
			} else {
				scheduler.Every(2).Hours().Run(scanJob)
			}
		}
	}
	if _, err := os.Stat(workList); !os.IsNotExist(err) {
		runTLSScan(ipSource, resolver)
	}
}

//RunTLSScan accepts generator of IP addresses to scan and a function to map the IPs to hostnames (if any) - function to allow the hostname resolution happen in parallel if necessary
func runTLSScan(ipSource func() []tlsmodel.GroupedHost, ipToHostnameResolver func(string) string) {
	//create a directory, if not exist, for tlsaudit to keep temporary file
	path := filepath.Join("data", "tlsaudit", "scan")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err2 := os.MkdirAll(path, 0755); err2 != nil {
			log.Errorln("Could not create the path ", path)
		}
	}

	//prevent concurrent runs
	if _, err := os.Stat(runFlag2); !os.IsNotExist(err) { // there is a runlock
		//do not start a new scan
		return
	}
	psr := tlsmodel.PersistedScanRequest{}

	if _, err := os.Stat(workList); !os.IsNotExist(err) { // there is a worklist (due to a previous crash!)
		//load the list of IPs from there
		println("Resuming due to a worklist")
		file, err := os.Open(workList)
		if err != nil {
			log.Error(err)
			return
		}
		defer file.Close()

		// scanner := bufio.NewScanner(file)
		// for scanner.Scan() {
		// 	hosts = append(hosts, scanner.Text())
		// }

		day, err := ioutil.ReadFile(runFlag)
		if err != nil {
			log.Error(err)
			return
		}
		d := strings.TrimSpace(string(day))
		println("Resuming on date ", d, filepath.Join(path, d))
		dirs, err := ioutil.ReadDir(filepath.Join(path, d))
		if err != nil {
			println(err.Error())
			log.Error(err)
			return
		}
		fmt.Printf("%#v\n", dirs)
		for _, sID := range dirs {
			scanID := sID.Name()
			println(scanID)
			if p, err := LoadScanRequest(d, scanID); err == nil {
				psr = p
				break
			}
		}
		fmt.Printf("Will be scanning with PSR %#v", psr)
	} else { // starting a fresh scan
		shuffledHosts := []string{}
		for _, gh := range ipSource() {
			//shuffle hosts randomly
			rand.Shuffle(len(gh.Hosts), func(i, j int) {
				gh.Hosts[i], gh.Hosts[j] = gh.Hosts[j], gh.Hosts[i]
			})
			psr.GroupedHosts = append(psr.GroupedHosts, gh)
			shuffledHosts = append(shuffledHosts, gh.Hosts...)
		}

		//write shuffled hosts into worklist file - we no longer rely on this for scanning, kept for debugging
		if err := ioutil.WriteFile(workList, []byte(strings.Join(shuffledHosts, "\n")+"\n"), 0644); err != nil {
			log.Error(err)
			return
		}

		//track progress in the progress file
		if err := ioutil.WriteFile(progress, []byte(fmt.Sprintf("-1,%d", len(shuffledHosts))), 0644); err != nil {
			log.Error(err)
			return
		}

		//create the lock file with the start day
		today := time.Now().Format(dayFormat)
		if err := ioutil.WriteFile(runFlag, []byte(today), 0644); err != nil {
			log.Error(err)
			return
		}

		if err := ioutil.WriteFile(runFlag2, []byte{}, 0644); err != nil {
			log.Error(err)
			return
		}
		psr.HostCount = len(shuffledHosts)
		request := tlsmodel.AdvancedScanRequest{}
		for _, gh := range psr.GroupedHosts {
			request.ScanGroups = append(request.ScanGroups, gh.ScanGroup)
		}
		request.Day = today
		request.ScanID = getNextScanID()
		config, _ := loadTLSConfig(TLSAuditConfigPath)
		scanConfig := tlsmodel.ScanConfig{
			PacketsPerSecond: config.PacketsPerSecond,
			Timeout:          config.Timeout,
		}
		request.Config = scanConfig
		psr.Request = request
	}

	//we've got the psr. Now use it as the basis of the scans
	hosts := []string{} // hosts to scan
	for _, gh := range psr.GroupedHosts {
		hosts = append(hosts, gh.Hosts...)
	}

	//get ready to scan
	//get where we "stopped" last time possibly after a crash
	stopped := 0
	p, err := ioutil.ReadFile(progress)
	if err != nil {
		log.Error(err)
		return
	}
	stopped, err = strconv.Atoi(strings.Split(string(p), ",")[0])
	if err != nil {
		log.Error(err)
		return
	}
	psr.Progress = stopped

	//only resolve IPs for the hosts that have not been scanned
	if stopped < len(hosts) {
		go resolveIPs(hosts[stopped:])
	}

	PersistScanRequest(psr)

	count := len(hosts)

	println(strings.Join(hosts, "\n"))
	//scan hosts
	for index, host := range hosts {
		//skip already scanned hosts, if any
		if index <= stopped {
			fmt.Printf("Skipping host %s\n", host)
			continue
		}
		counter := index + 1
		scan := make(map[string]tlsmodel.ScanResult)
		// results := []<-chan tlsmodel.ScanResult{}
		scanResults := []tlsmodel.ScanResult{}
		fmt.Printf("Scanning Host %s (%d of %d)\n", host, counter, count)
		for _, result := range ScanCIDRTLS(host, psr.Request.Config) {
			// results = append(results, ScanCIDRTLS(host, psr.Request.Config))
			// for result := range MergeResultChannels(results...) {
			key := result.Server + result.Port
			if _, present := scan[key]; !present {
				scan[key] = result
				scanResults = append(scanResults, result)
				println("Got result for ", result.Server, ipToHostnameResolver(result.Server), result.Port, result.SupportsTLS(), result.IsSTARTTLS, fmt.Sprintf("%#v", result.SupportedProtocols))
			}
		}
		sort.Sort(tlsmodel.ScanResultSorter(scanResults))
		PersistScans(psr, host, Humanise(scanResults))

		if err := ioutil.WriteFile(progress, []byte(fmt.Sprintf("%d,%d", counter, len(hosts))), 0644); err != nil {
			log.Error(err)
			return
		}

		psr.Progress = counter
		PersistScanRequest(psr)
	}

	//cleanup
	if err := os.Remove(runFlag); err != nil {
		log.Error(err)
	}
	if err := os.Remove(runFlag2); err != nil {
		log.Error(err)
	}
	if err := os.Remove(progress); err != nil {
		log.Error(err)
	}
	if err := os.Remove(workList); err != nil {
		log.Error(err)
	}
}

func loadTLSConfig(path string) (config tlsmodel.TLSAuditConfig, e error) {
	configFile, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error(err)
		return config, err
	}
	err = yaml.Unmarshal(configFile, &config)
	if err != nil {
		log.Error(err)
		return config, err
	}
	return

}

type sorter []tlsmodel.ScanResult

func (k sorter) Len() int {
	return len(k)
}

func (k sorter) Swap(i, j int) {
	k[i], k[j] = k[j], k[i]
}
func (k sorter) Less(i, j int) bool {
	iPort, _ := strconv.Atoi(k[i].Port)
	jPort, _ := strconv.Atoi(k[j].Port)
	return k[i].Server < k[j].Server || (k[i].Server == k[j].Server && iPort <= jPort)
}
