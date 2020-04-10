package assets

//Report is the diagnostic report template
var Report = `:title-page:
:title-logo-image: image:{{ .Logo }}[top=25%, align=center, pdfwidth=4.0in]
:icons: font
:author: https://github.com/adedayo/tlsaudit v{{ .TLSAuditVersion}}
:email: dayo@securityauditlabs.com
:revdate: {{ .TimeStamp }}
:description: A server security audit
:sectnums:
:icons: font
:listing-caption:
:red: #ff0000
:blue: #0000ff
:green: #00ff00

= TLS Audit Report: image:{{ .SALLogo }}[align=center, pdfwidth=0.2in] Server security audit 
:source-highlighter: rouge

== Executive Summary
This is a report of the security audit of your server(s) conducted on {{ .TimeStamp }}

[cols="2a,5a",%autowidth.stretch,frame=none,grid=none]
|===

^.^|[cols="1",frame=none,grid=none]
!===
^!Worst Measured Grade
a!image::{{ .WorstGrade }}[align=center, pdfwidth=1.0in]
!===

|image::{{ .Chart }}[align=center, pdfwidth=4.0in]

|===

[NOTE] 
.Interpretation of Worst Measured Grade
====
{{ range $index, $advisory := .WorstGradeAdvisories }}
* {{ $advisory }}
{{ end }}

[cols="2,10,2", options="header", stripes=even, grid=cols]
.Grade Legend and count of occurrence
|===
| Grade | Meaning | Number Found
{{ generateGradeLegend .Summary.GradeToHostPorts }}
|===
====


<<<

== Detailed Metrics

The following are some details and result metrics from the TLS Audit.

[cols="2,5",stripes=even,%autowidth.stretch]
.TLS Audit Metrics 
|===
| Worst Grade observed | {{ .Summary.WorstGrade }} (on {{ .Summary.WorstGradeExample.Server }}:{{ .Summary.WorstGradeExample.Port }})
| Best Grade observed | {{ .Summary.BestGrade }} (on {{ .Summary.BestGradeExample.Server }}:{{ .Summary.BestGradeExample.Port }})
| Total Number of Hosts (IPs) | {{ .Summary.HostCount }}
| Total number of Ports (Unique IP:Port(s))| {{ .Summary.PortCount }}
{{ generateGradeTable .Summary.GradeToHostPorts }}
{{ generateGradeRangeTable .Summary.HostGrades}}
|===

<<<

== Details of Individual Scan Results

The following sections contain detailed description of results for each port that implements SSL/TLS



{{ range $index, $scan := .ScanResults }}
{{ template "SCANRESULT" $scan }}
<<<
{{ end }}



{{ define "SCANRESULT" }}

[big]*TLS Audit Report for {{ .HumanScanResult.Server }} ({{ .HumanScanResult.HostName }}) on Port {{ .HumanScanResult.Port }}*

{{ template "SCANHEADER" "Summary"}}

[cols="2a,5a",%autowidth.stretch,frame=none,grid=none]
|===
^.^|[cols="1",frame=none,grid=none]
!===
^!Overall Grade
a!image::{{ .Grade }}[align=center, pdfwidth=1.0in]
!===
|image::{{ .Chart }}[align=center, pdfwidth=4.0in]
|===

[NOTE] 
.Advisories
====
* Grade {{ .HumanScanResult.Score.Grade }} :  _{{ interpretGrade .HumanScanResult.Score.Grade }}_
{{ range $index, $advisory := .HumanScanResult.Score.Warnings }}
* {{ $advisory }}
{{ end }}
====

<<<


{{ range $index, $certs := getCerts .HumanScanResult }}
'''
{{ $cert := index $certs 0 }}
{{ template "SCANHEADER" printf "Certificate number #%d: %s %s (%s)" (inc $index) $cert.PublicKeyAlgorithm $cert.Key $cert.SignatureAlgorithm }}
{{ with $cert }}
[cols="2,5",options="header",frame=none,grid=none,stripes=even]
|===
2+|Server Key and Certificate #{{ inc $index }}
|Subject | {{ .Subject }}
|Subject Serial Number | {{ .SubjectSerialNo }}
|Common Names|  {{ .SubjectCN }}
|Alternative Names| {{ .SubjectAN }}
|Serial Number| {{ .SerialNumber }}
|Valid From| {{ .ValidFrom }}
|Valid Until| {{ .ValidUntil }}
|Key Algorithm| {{ .PublicKeyAlgorithm }}
|Key| {{ .Key }}
|Issuer| {{ .Issuer }}
|Signature Algorithm| {{ .SignatureAlgorithm }}
|Signature| {{ .Signature }}
|OCSP Must Staple| {{ .OcspStapling }}
|Certificate Version| {{ .Version }}
|Chain Length | {{ len $certs }}
{{ range $i, $c := describeCerts $certs }}
[small]#{{ $c }}#
{{ end }}
|===
{{ end }}
{{ end }}



{{ template "SCANHEADER" "Configuration" }}
[cols="1",options="header",frame=none,grid=none,stripes=even]
|===
|Supported Protocols
{{ range $i, $proto := .SupportedProtocols }}
| {{ $proto }}
{{ end }}
|===

'''

[cols="5,1",options="header",frame=none,grid=none,stripes=even]
|===
2+|Cipher Suites
{{ generateCipherTable .HumanScanResult }}
|===


<<<
{{ end }}


{{ define "SCANHEADER" }}
[cols="a^.^",%autowidth.stretch,stripes=odd]
|===
|[big]*{{ . }}*
|===
{{ end }}
`
