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

[cols="1,10", options="header", stripes=even, grid=none]
.Grade Legend
|===
| Grade | Meaning
{{ generateGradeLegend .Summary.GradeToHostPorts }}
|===
====


<<<

== Detailed Metrics

Distribution of Grades Measured Across Your Servers

image::{{ .Chart }}[align=center, pdfwidth=4.0in]
[NOTE]
====
[cols="1,10", options="header", stripes=even]
.Grade Legend
|===
| Grade | Meaning
{{ generateGradeLegend .Summary.GradeToHostPorts }}
|===
====

=== Metrics 

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


== Individual Results

[cols="2a,5a",%autowidth.stretch,frame=none,grid=none]
|===

^.^|[cols="1",frame=none,grid=none]
!===
^!Overall Grade
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

[cols="1,10", options="header", stripes=even, grid=none]
.Grade Legend
|===
| Grade | Meaning
{{ generateGradeLegend .Summary.GradeToHostPorts }}
|===
====



{{ define "SCANRESULT" }}

{{ end }}
`
