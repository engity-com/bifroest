{{range .}}{{printf "%q\t%q\t%q\t%q\n" .Name .Version .LicenseName .LicenseText}}{{end}}
