package gost

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"github.com/golang/glog"
	"net"
	"strings"
	"time"
)

const (
	Version = "2.4-dev"
)

// Log level for glog
const (
	LFATAL = iota
	LERROR
	LWARNING
	LINFO
	LDEBUG
)

var (
	KeepAliveTime = 180 * time.Second
	DialTimeout   = 30 * time.Second
	ReadTimeout   = 90 * time.Second
	WriteTimeout  = 90 * time.Second

	DefaultTTL = 60 // default udp node TTL in second for udp port forwarding
)

var (
	SmallBufferSize  = 1 * 1024  // 1KB small buffer
	MediumBufferSize = 8 * 1024  // 8KB medium buffer
	LargeBufferSize  = 32 * 1024 // 32KB large buffer
)

var (
	DefaultCertFile = "cert.pem"
	DefaultKeyFile  = "key.pem"

	// This is the default cert and key data for convenience, providing your own cert is recommended.
	defaultRawCert = []byte(`-----BEGIN CERTIFICATE-----
MIIC5zCCAc+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQqEwRwYW5k
MB4XDTE3MDUwNzE5NDEzOFoXDTIwMDYwNTE5NDEzOFowDzENMAsGA1UEKhMEcGFu
ZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANasayyO5SHnwSupg6IJ
acOA1WOoxDy1OiLUy6UNWu1WiDn1vTsaZa2TnMS94CJtg+k0yFTvkJSsXlg/Xevg
GUUhTIkiX1VuOqigd2k1sksf12Iiz5WPsMmp+tDlucbuJL3LNJithBis+SEJZIR0
Y6Zd4fVFhnVRDzYEYBkYLcg0XuhlY480TvPPCNNcn4vv+jk1RmuXbI8M5oioBCfX
gwDImE4bRzwI9+cdM4XbLNRdbU+g4i/4xmqFNgYPCGp/93CEOoAJ/t8EcvjA1HkM
injHXKWhuR5Hw1NMGNWGNLYeWXWSygoY3b/rmTloiYf7dKbIA7nOFxvFTzwjknRM
4X0CAwEAAaNOMEwwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMB
MA8GA1UdEwEB/wQFMAMBAf8wFAYDVR0RBA0wC4IJbG9jYWxob3N0MA0GCSqGSIb3
DQEBCwUAA4IBAQCbhVLC+VcHgcqkIGB91osijGttQfiE59aayerStShRquLnnnyr
w6H/imwYjqzzjTePBeWikTv1wYxS3PxfpqlMBWMPWVewPURVK6lKn/kc5jz0stPb
8ScpG1xl3KijxtZxcpFKMnETD7B8dJ3UKQifetXtJ2G6nAAYol0Fq5go2JYAUFC/
gHHfst9gOai0AV7kcdkFDPXiGf4tfeQL82lc24dannAhnrvsgPOPTHWL5NTcwDzg
1w3PxYx+leVdAYeGvk0Pl6crfwv3FAuIAB8o7TEA1jgQTB8u+ncgruERFMT41/Mm
MZKmycp2ppfcgffVR2I60TrRbYV9ihLdo58o
-----END CERTIFICATE-----`)
	defaultRawKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1qxrLI7lIefBK6mDoglpw4DVY6jEPLU6ItTLpQ1a7VaIOfW9
OxplrZOcxL3gIm2D6TTIVO+QlKxeWD9d6+AZRSFMiSJfVW46qKB3aTWySx/XYiLP
lY+wyan60OW5xu4kvcs0mK2EGKz5IQlkhHRjpl3h9UWGdVEPNgRgGRgtyDRe6GVj
jzRO888I01yfi+/6OTVGa5dsjwzmiKgEJ9eDAMiYThtHPAj35x0zhdss1F1tT6Di
L/jGaoU2Bg8Ian/3cIQ6gAn+3wRy+MDUeQyKeMdcpaG5HkfDU0wY1YY0th5ZdZLK
Chjdv+uZOWiJh/t0psgDuc4XG8VPPCOSdEzhfQIDAQABAoIBABEfIVEleHryzAJa
e8gxrgDMxrgzHquk3KUoibF5VjY1v5m30sbi/RcR/d/nMPgt+eZgslWr4cEp2kB5
lVkZv4o29K6/UhEzQHRwj/WRNc4uFPSbyCiqlDQRXZLJr76BAectTN2cgTuimCAd
aqnxynzbYgk46Vd0Bp2NTcjSl9wuw6mQBNIz8oIpD0G7z2acAnBhE2ehbn0/9upq
VmUNdoiuxwCbU++bIB36fjvDDTfok0+3NdKGekUMaggyvWRFIhzSaZfexULvf+VF
OtarJAvN7DyNZybTrkqZe2+lkJ0uZx6bj0UVMD7ieLZH+uirMkz4lsqNUODrQn1t
6Jd9uCECgYEA+JCPAjV/51U5Ya85YKP1qWOiYLkdO53zFIyL2s6Kdj4lUrA8cXrR
bEqaNlKU76J63CI97i7CUbzLRWETgqxh46e02VFszXQY7LTgrxYoFeqceIU1GjLS
byDKLHxlPmuCJg6WlYyX1n8kcNq/29xp2P9x2CP3DDKHhbyX83NTEhkCgYEA3RhU
n3ET7EqccLCAPtYt4rdUgwYjGusBa/9H9K4WEcw40AFf3IRJiIVQ4DGYX6CU+kQ7
pc1hhCEhX9cMMcvnNHQztkoSb65fUChLsWo9aRj355SpwgZOPWjVYJyq0Wyya98j
4clYm04pkjhTTZh2ef+lhhZARZ9UP01GqUTwnwUCgYEAqkpHX4kNlowhotXsJlRO
An2bCk7oQybEGUjsq7wiyj1rTook7s3o2hsGKb9MABy9tUDUUvC/+kWwsVh/iF/X
NKN52ATb2Kn4RXrqD6nLTrCMAFmqdsdoue+p8u5KYog/Axmtesl2YOJ8McD7/oG0
FpFzClQhdb7McAgzxfs1Z0kCgYAdpMx70Dp+nQZaqZ+YTTk7w57mLmV4j3fSVhj8
unalDj+zy+thcq81ScKtPJkUgUBYSdvBgEcJ4zNJWVj+ODuYsdfZIhdUuAl5gt2b
PQZc2ActGqakKBpHa43odTkF+U/23KU/+bISqKk0PK8WoVGJS/iSgNs/OnyePCs0
ONUWTQKBgQCVVjhFPgTcGFyOBZlU5l2IQQnTy17OPSDMWdVekDdbDF3+2jGxpMWN
9K9bt806zEWWCNrULdiGBblL/txQ1hgL1c2lZXSxnzamZmJtKWeJ7OHg69WE5gXL
DFMmjOTmN3gelJTIA5Zqarzb6DcxwMGxjc+6m/47oNF17bl87ElYLw==
-----END RSA PRIVATE KEY-----`)
)

var (
	ErrEmptyChain = errors.New("empty chain")
)

func setKeepAlive(conn net.Conn, d time.Duration) error {
	c, ok := conn.(*net.TCPConn)
	if !ok {
		return errors.New("Not a TCP connection")
	}
	if err := c.SetKeepAlive(true); err != nil {
		return err
	}
	if err := c.SetKeepAlivePeriod(d); err != nil {
		return err
	}
	return nil
}

// Load the certificate from cert and key files, will use the default certificate if the provided info are invalid.
func LoadCertificate(certFile, keyFile string) (tls.Certificate, error) {
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err == nil {
		return tlsCert, nil
	}
	glog.V(LWARNING).Infoln(err)
	return tls.X509KeyPair(defaultRawCert, defaultRawKey)
}

// Replace the default certificate by your own
func SetDefaultCertificate(rawCert, rawKey []byte) {
	defaultRawCert = rawCert
	defaultRawKey = rawKey
}

func basicProxyAuth(proxyAuth string) (username, password string, ok bool) {
	if proxyAuth == "" {
		return
	}

	if !strings.HasPrefix(proxyAuth, "Basic ") {
		return
	}
	c, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(proxyAuth, "Basic "))
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}

	return cs[:s], cs[s+1:], true
}
