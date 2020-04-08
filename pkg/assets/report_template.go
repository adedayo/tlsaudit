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
:listing-caption:
:red: #ff0000

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
| Total number of Ports (Unique IP:Port(s))| pass:a[<background_color rgb="{red}">{{ .Summary.PortCount }}</background_color>]
{{ generateGradeTable .Summary.GradeToHostPorts }}
{{ generateGradeRangeTable .Summary.HostGrades}}
|===

<<<

== Details of Individual Scan Results

The following sections contain detailed description of results for each port that implements SSL/TLS



{{ range $index, $scan := .ScanResults }}
{{ template "SCANRESULT" $scan }}
{{ end }}



{{ define "SCANRESULT" }}
=== TLS Audit Report for {{ .HumanScanResult.Server }} ({{ .HumanScanResult.HostName }}) on Port {{ .HumanScanResult.Port }}

[cols="2a,5a",%autowidth.stretch,frame=none,grid=none]
|===

^.^|[cols="1",frame=none,grid=none]
!===
^!Overall Grade
a!image::{{ .Grade }}[align=center, pdfwidth=1.0in]
!===

|image::{{ .Chart }}[align=center, pdfwidth=4.0in]

|===

{{ end }}
`
