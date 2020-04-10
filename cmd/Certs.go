package main

import (
	"00pf00/Certs/pkg/cert"
	"00pf00/Certs/pkg/util"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

const (
	CN  = "proxy"
	CP  = "/Users/feeli/workspace/Certs/src/00pf00/Certs/conf/cluster.crt"
	KP  = "/Users/feeli/workspace/Certs/src/00pf00/Certs/conf/cluster.key"
	SCP = "/Users/feeli/workspace/Certs/src/00pf00/Certs/conf/server.crt"
	SCK = "/Users/feeli/workspace/Certs/src/00pf00/Certs/conf/server.key"
	CCP = "/Users/feeli/workspace/Certs/src/00pf00/Certs/conf/client.crt"
	CCK = "/Users/feeli/workspace/Certs/src/00pf00/Certs/conf/client.key"
)

func main() {
	cb, err := ioutil.ReadFile("/Users/feeli/workspace/Certs/src/00pf00/Certs/conf/cluster.crt")
	if err != nil {
		fmt.Printf("load cert file fail! err = %v", err)
		return
	}
	ck, err := ioutil.ReadFile("/Users/feeli/workspace/Certs/src/00pf00/Certs/conf/cluster.key")
	if err != nil {
		fmt.Printf("load key  file fail! err = %v", err)
		return
	}

	crt, err := tls.X509KeyPair(cb, ck)
	if err != nil {
		fmt.Printf("parase cert fail! err = %v", err)
		return
	}
	certs, err := x509.ParseCertificates(crt.Certificate[0])
	if err != nil {
		fmt.Println("get cert fail err = %v", err)
		return
	}
	crt.Leaf = certs[0]
	fmt.Println(crt.Leaf.DNSNames)

	getServerCerts(crt)
}
func getServerCerts(crt tls.Certificate) {
	dns := []string{"cls-qwyg220a-proxy.ccs.tencent-cloud.com"}
	//dns :=  []string{};
	//ips := [] string{"127.0.0.1"}
	ips := [] string{}
	serverCN := "proxy"
	sc, sk, err := cert.GenerateServerCertAndKey(crt.Leaf, crt.PrivateKey.(*rsa.PrivateKey), serverCN, ips, dns)
	if err != nil {
		fmt.Println("get server cert and key fial ")
		return
	}
	ioutil.WriteFile(SCP, util.EncodeCertPEM(sc), 0777)
	ioutil.WriteFile(SCK, util.EncodeKeyPEM(sk), 0777)
}
func getClientCerts(crt tls.Certificate) {
	clientcert, clientkey, err := cert.GenerateClientCertAndKey(crt.Leaf, crt.PrivateKey.(*rsa.PrivateKey), CN)
	if err != nil {
		fmt.Println("get client cert and key fail ! err = %v", err)
		return
	}
	ioutil.WriteFile(CCP, util.EncodeCertPEM(clientcert), 0777)
	ioutil.WriteFile(CCK, util.EncodeKeyPEM(clientkey), 0777)
}
