package version

// Version represents the release identifier formatted as CalVer (YYYY.0M.MICRO).
const Version = "2026.10.0"

// UserAgent returns the HTTP User-Agent header value identifying bugrouter.
func UserAgent() string {
	return "bugrouter/" + Version + " (+https://github.com/riccivr/bugrouter)"
}
