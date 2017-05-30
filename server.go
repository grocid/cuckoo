package main

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "io/ioutil"
    "log"
    "net"
    "net/http"
    "time"
    "math/rand"
    "encoding/json"
)

var connected = make(map[string]int64)

func announce(w http.ResponseWriter, req *http.Request) {
    ip, _, _ := net.SplitHostPort(req.RemoteAddr)
    connected[ip] = time.Now().UnixNano() + 1000000000 * 60

    // Update list
    for key := range connected {
        if connected[key] < time.Now().UnixNano() {
            delete(connected, key)
        }
    }
}

func get(w http.ResponseWriter, req *http.Request) {
    json, _ := json.Marshal(connected)
    fmt.Fprintf(w, "%s", json)
}

func main() {
    rand.Seed(time.Now().UnixNano())

    certBytes, err := ioutil.ReadFile("tls.crt")
    if err != nil {
        log.Fatalln("Unable to read certificate", err)
    }

    clientCertPool := x509.NewCertPool()
    if ok := clientCertPool.AppendCertsFromPEM(certBytes); !ok {
        log.Fatalln("Unable to add certificate to certificate pool")
    }

    tlsConfig := &tls.Config{
        // Reject any TLS certificate that cannot be validated
        ClientAuth: tls.RequireAndVerifyClientCert,
        // Ensure that we only use our "CA" to validate certificates
        ClientCAs: clientCertPool,
        // PFS because we can
        CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
        // Force it server side
        PreferServerCipherSuites: true,
        // TLS 1.2 because we can
        MinVersion: tls.VersionTLS12,
    }

    tlsConfig.BuildNameToCertificate()

    http.HandleFunc("/announce", announce)
    http.HandleFunc("/get", get)

    httpServer := &http.Server{
        Addr:      ":8080",
        TLSConfig: tlsConfig,
    }
    log.Println(httpServer.ListenAndServeTLS("tls.crt", "tls.key"))
}