package cert

import (
	"00pf00/Certs/pkg/util"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	certutil "k8s.io/client-go/util/cert"
	"math"
	"math/big"
	"net"
	"time"
)

func GenerateServerCertAndKey(caCert *x509.Certificate, caKey *rsa.PrivateKey, serverCN string, ips []string, dns []string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certIps := []net.IP{}
	for _, ip := range ips {
		certIps = append(certIps, net.ParseIP(ip))
	}
	//needs to verify ip first
	config := &certutil.Config{
		CommonName: serverCN,
		AltNames: certutil.AltNames{
			DNSNames: dns,
			IPs:      certIps,
		},
		Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	return generateCertAndKeyConfig(caCert, caKey, config)
}

func generateCertAndKeyConfig(caCert *x509.Certificate, caKey *rsa.PrivateKey, config *certutil.Config) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := util.NewPrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate private key %+v", err)
	}
	cert, err := NewSignedCert(config, key, caCert, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate cert %+v", err)
	}
	return cert, key, nil
}

// NewSignedCert creates a signed certificate using the given CA certificate and key
func NewSignedCert(cfg *certutil.Config, key crypto.Signer, caCert *x509.Certificate, caKey crypto.Signer) (*x509.Certificate, error) {
	serial, err := cryptorand.Int(cryptorand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	if len(cfg.CommonName) == 0 {
		return nil, fmt.Errorf("must specify a CommonName")
	}
	if len(cfg.Usages) == 0 {
		return nil, fmt.Errorf("must specify at least one ExtKeyUsage")
	}

	certTmpl := x509.Certificate{
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: cfg.Organization,
		},
		DNSNames:     cfg.AltNames.DNSNames,
		IPAddresses:  cfg.AltNames.IPs,
		SerialNumber: serial,
		NotBefore:    caCert.NotBefore,
		NotAfter:     time.Now().Add(duration365d).UTC(),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  cfg.Usages,
	}
	certDERBytes, err := x509.CreateCertificate(cryptorand.Reader, &certTmpl, caCert, key.Public(), caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDERBytes)
}

func GenerateClientCertAndKey(caCert *x509.Certificate, caKey *rsa.PrivateKey, clientCN string) (*x509.Certificate, *rsa.PrivateKey, error) {
	clientCertConfig := &certutil.Config{
		CommonName:   clientCN,
		Organization: []string{"system:masters"},
		Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return generateCertAndKeyConfig(caCert, caKey, clientCertConfig)
}
