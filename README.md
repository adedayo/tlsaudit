[![Build Status](https://travis-ci.org/adedayo/tlsaudit.svg?branch=master)](https://travis-ci.org/adedayo/tlsaudit)

# TLSAudit 
TLSAudit is a utility for auditing TLS (including SSL and STARTTLS) security settings. You can use it to enumerate protocols, ciphers and curves supported by an open TCP port. Scan entire CIDR ranges with TLSAudit to discover which ports are open and get details of the TLS configurations of the open ports. You can scan specific port ranges within CIDR ranges too, by using a format such as `tlsaudit 10.10.5.0:443/24`, which scans the entire CIDR range `10.10.5.0/24` but looking only at port `443`. 

## Using it as a command-line tool
TLSAudit is also available as a command-line tool. 

### Installation
Prebuilt binaries may be found for your operating system here: https://github.com/adedayo/tlsaudit/releases

For macOS X, you could install via brew as follows:
```bash
brew tap adedayo/tap
brew install tlsaudit
``` 

### Scanning CIDR ranges

```bash
tlsaudit 8.8.8.8 192.168.2.5/30 10.11.12.13:443/31
```

For JSON-formatted output simply add the `--json` or `-j` flag:

```bash
tlsaudit --json 8.8.8.8 192.168.2.5/30 10.11.12.13:443/31
```
Depending on the fidelity of the network being scanned or the size of CIDR ranges, it may be expedient to adjust the scan timeout and the number of packets per second to send during the open port discovery phase. Several scanning options are available. See the options from the commandline help.

### Command line options

```bash
   --json, -j                     generate JSON output (default: false)
   --protocols-only, -p           only check supported protocols (will not do detailed checks on supported ciphers) (default: false)
   --hide-certs, -c               suppress certificate information in output (default: false)
   --quiet, -q                    control whether to produce a running commentary of progress or stay quiet till the end (default: false)
   --timeout TIMEOUT, -t TIMEOUT  TIMEOUT (in seconds) to adjust how much we are willing to wait for servers to come back with responses. Smaller timeout sacrifices accuracy for speed (default: 5)
   --rate value, -r value         the rate (in packets per second) that we should use to scan for open ports (default: 1000)
   --output FILE, -o FILE         write results into an output FILE (default: "tlsaudit.txt")
   --input FILE, -i FILE          read the CIDR range, IPs and domains to scan from an input FILE separated by commas, or newlines (default: "tlsaudit_input.txt")
   --help, -h                     show help (default: false)
   --version, -v                  print the version (default: false)
```

## An issue on macOS
You may encounter errors such as 
```bash
panic: en0: You don't have permission to capture on that device ((cannot open BPF device) /dev/bpf0: Permission denied)
```
Fix the permission problem permanently by using the "Wireshark" approach of pre-allocating _/dev/bpf*_, and changing their permissions so that the _admin_ group can read from and write packets to the devices. I have provided the _fix-bpf-permissions.sh_ script to simplify the steps, you can run it as shown below. It will ask for your password for the privileged part of the script, but read the script to satisfy yourself that you trust what it is doing! You care about security, right?

```bash
curl -O https://raw.githubusercontent.com/adedayo/tlsaudit/master/fix-bpf-permissions.sh
chmod +x fix-bpf-permissions.sh
./fix-bpf-permissions.sh  
```

You should be good to go! You may need to reboot once, but this works across reboots. Note that this is a common problem for tools such as Wireshark, TCPDump etc. that need to read from or write to /dev/bpf*. This solution should fix the problem for all of them - the idea was actually stolen from Wireshark with some modifications :-).

## Running as non-root on Linux
You ideally want to be able to run `tlsaudit` as an ordinary user, say, `my_user`, but since `tlsaudit` sends raw packets you need to adjust capabilities to allow it to do so. The following may be necessary:

Ensure the following two lines are in _/etc/security/capability.conf_
```bash
cap_net_admin   my_user
none *
```

Also, in _/etc/pam.d/login_ add the following 
```bash
auth    required        pam_cap.so
```

Finally, grant the capability to the `tlsaudit` file (assuming _/path/to_ is the absolute path to your `tlsaudit` binary)
```bash
setcap cap_net_raw,cap_net_admin=eip /path/to/tlsaudit
```
## License
BSD 3-Clause License