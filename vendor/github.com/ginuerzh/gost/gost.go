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
MB4XDTE3MDUwOTE1NDUwNFoXDTIwMDYwNzE1NDUwNFowDzENMAsGA1UEKhMEcGFu
ZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK6dbfqF0LSRZEIyndIB
Af2z10p4JcTs5CA9z0kM66cxIMEyoo4Gk+RX/LgZulutTOUEKOUcevFv04+yAAY2
652rztt37BxPdiioxY8Aj9AovypqcFmxhGravGTvKegpaErgHKOXLH0x898e1mLJ
TwP1evPvBQCcPh4Ki6nd0U1oYM39HPxc5vwlePK1S7DdgYwUb46RBhPuMzZ9KqIV
Mr1R9YgiWcL8VVf1QEl4R5DXxNAmdi4M1Wq4UPcTJtLvtB+6/hhjr5TaWAVkNPiN
3MQdijPvTxFFA5/jXXyDdV417JbIn6obOl5WVAaOthzySa8SoeqrqtfMH+i9y2rp
BkMCAwEAAaNOMEwwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMB
MA8GA1UdEwEB/wQFMAMBAf8wFAYDVR0RBA0wC4IJbG9jYWxob3N0MA0GCSqGSIb3
DQEBCwUAA4IBAQCYBUIZgYeifv5aZMtLKKH2parQlNxWvb4mKieYeN40j3VQiKW8
oWcuPE5SHuNQRHsCVHbok7uWrULreT+WQVqLbefHBv8tiNsSRprYSa4qOxZVt0Ri
Yc9dZp9YIRCx4TGYbVoDQMWcC4tYLnZ41Y/9KKa/ARJTcDhGgN0E8jILHuihgfZb
+MmWWV8vI1bp8yJxiWxizYyTd9phVQPl8egdqn1nkFYVQxF7f2lHz4fa1YZO6oPs
CZWox/rnPPYiDGzL0MyT8mtSZ2VaEX14Qb0oFUWuNXvkODzUy+DbKiDdXJa632nq
6UYCLwJIaq5nmTdaxyfW68hOVxZAU7WPuN08
-----END CERTIFICATE-----`)
	defaultRawKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEArp1t+oXQtJFkQjKd0gEB/bPXSnglxOzkID3PSQzrpzEgwTKi
jgaT5Ff8uBm6W61M5QQo5Rx68W/Tj7IABjbrnavO23fsHE92KKjFjwCP0Ci/Kmpw
WbGEatq8ZO8p6CloSuAco5csfTHz3x7WYslPA/V68+8FAJw+HgqLqd3RTWhgzf0c
/Fzm/CV48rVLsN2BjBRvjpEGE+4zNn0qohUyvVH1iCJZwvxVV/VASXhHkNfE0CZ2
LgzVarhQ9xMm0u+0H7r+GGOvlNpYBWQ0+I3cxB2KM+9PEUUDn+NdfIN1XjXslsif
qhs6XlZUBo62HPJJrxKh6quq18wf6L3LaukGQwIDAQABAoIBAGNA0TbJwWwiCJ8o
LlUkhYE0LHgD+1QIY1OATsbzNS//2OJ4abXZP09YRCpRVYCu7TpwNt6kZa2/Jr5T
K3hc12j0M8zESc19zWgnJsS2SQjFYIQ3pE0XfnFOjC/DUkrI3qNQ6HaEg6FWN4zn
9myIiQVzD8SAZJOIPDbPP7v6ffJFJe5wr6Rx7xvnnadyNqL+Y8FQpxc3yO7KXsYd
xS2OdKuIDiHmThpe/kFeWTMzgdqflDr6T4+5rG/cJTjqZoub9IMNL0cnEtwQMg0l
bR0Q9Peo8ddG4HLiMe3MmzgrZ3B+sFCIN3LwRDpvTK9WJyaMm91rMCZcC9jODAHy
FH1fg8ECgYEA2UzgVuo4oOVQqa35S4xMiuvS9uMPlms02k0oJD0KckuKqIYblCa5
waB1jiny7OnHvzdm7NP68L+8jKiMH5zlFmr49kJG2ELs+aoGcWPC0MVGpe8HCVAf
jIHVA8yxwrNfvaahsVDQjrxnhHQdxmw0PN9KAtNUEwUQ+xaPHDdVCNkCgYEAzbZz
Erp4XTHAUe11naS13IqemXbtjBeI5uLQSb78m3x+ePLShC7nSJaeU+jXbWmdtIsK
nhd09eSDRwjYyFTIq59AE6BpWunHqtkaIHmezc/1XbYurBwBSO/Unhmovih/zx5i
TmY2lQS6x/6dwLw79USBlJuBXD/1B2iOr1CwNnsCgYBhx5gDRC3rKITddW2CM0WW
FXu+oHm5I9CKksGHXPhAagGgx4fNaIeZu0xqhjHLrX62aoWj99cpUf3UBVvYNc9Y
ARa6KSSb17GuvnVbvJpDOyIJNL+jzywDG8DwjsFGbVSdkEed9FGEiP7DuURUrwfq
hEdXciSY0mTLt2D6P2PCMQKBgECh9W/J9K1bR1C2agDY0mbzircu/Z3JezMHymeR
QS7dI6N+r5PmZLaS1DYK7zyqNWmXUgOv3Qiw/mogJnRy5wW9KFXCTbfJwfk08xeG
/tUtZKtH5UwgFGtFJylxaGousVFy+3IkfTu+26ygnBIFUlVSa+A0J6XDVoo4WLRO
hr7nAoGBAMM1HR/07JuXo65VveaJgDGEhAfp9mUR2csmfRYnIW8Ow15NBnsrsmP1
bjhR6goWg3/AOmwhyQ+cBCUPw+EUtGWazBTBal6CZA2UeDzOyROMZJvxEj+fkHdw
ERw6jZFwyQ+Bgf87rmPEY66e1S6Pjdd8GpIFGSV7sLVVxW1V9UVv
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
