package main

import (
    "crypto/tls"
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "syscall"
    "time"
)

//Implements net.Conn for custom TFO logic
type tfoConn struct {
    fd         int
    init       bool
    localAddr  net.Addr
    remoteAddr net.Addr
    socketAddr syscall.Sockaddr
}

/***Begin TFO overrides for net.Conn interface***/
func (c *tfoConn) Read(msg []byte) (int, error) {
    return syscall.Read(c.fd, msg)
}

func (c *tfoConn) Write(msg []byte) (int, error) {
    //Use sendto syscall with MSG_FASTOPEN for first write only to establish socket without connect syscall
    if c.init {
        c.init = false
        err := syscall.Sendto(c.fd, msg, syscall.MSG_FASTOPEN, c.socketAddr)
        if err != nil {
            return 0, err
        }
        return len(msg), nil
    }
    //Standard write for subsequent writes (after initial TFO)
    return syscall.Write(c.fd, msg)
}

func (c *tfoConn) Close() error                       { return syscall.Close(c.fd) }
func (c *tfoConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *tfoConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *tfoConn) SetDeadline(t time.Time) error      { return nil }
func (c *tfoConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *tfoConn) SetWriteDeadline(t time.Time) error { return nil }
/***End TFO overrides for net.Conn interface***/

//Open and return a TFO-initialized socket, expects IPv4 host
func openTFO(host string, port int) *tfoConn {
    ipv4 := net.ParseIP(host).To4()
    if ipv4 == nil {
        log.Fatalf("Expected IPv4 address")
    }

    //Create TCP socket
    fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
    if err != nil {
        log.Fatalf("Failed to create socket: %v", err)
    }

    //Build socket address struct
    var addr [4]byte
    copy(addr[:], ipv4)
    sa := &syscall.SockaddrInet4{
        Addr: addr,
        Port: port,
    }

    //Wrap socket file descriptor and address struct with custom TFO net.Conn
    conn := &tfoConn{
        fd:         fd,
        init:       true,
        localAddr:  &net.TCPAddr{IP: net.IPv4zero, Port: 0},
        remoteAddr: &net.TCPAddr{IP: ipv4, Port: port},
        socketAddr: sa,
    }

    //fmt.Printf("%+v\n", conn)
    return conn
}

//Makes https GET request using TFO connection
func httpsGetTFO(host string, port int, path string, body string) []byte {
    conn := openTFO(host, port)

    //Configure TLS (skipping cert verification for now)
    tlsConfig := &tls.Config{
        InsecureSkipVerify: true,
        ServerName:         host,
    }
    tlsConn := tls.Client(conn, tlsConfig)
    defer tlsConn.Close()

    /* TLS handshake part...
     * crypto/tls writes its ClientHello message here but uses
     * tfoConn override for using sendto() + MSG_FASTOPEN, bypassing connect() syscall
     */
    if err := tlsConn.Handshake(); err != nil {
        log.Fatalf("TLS Handshake failed: %v", err)
    }

    //Write GET request over established socket
    req := fmt.Sprintf(body)
    _, err := tlsConn.Write([]byte(req))
    if err != nil {
        log.Fatalf("Failed to send HTTP request: %v", err)
    }

    //Read response
    response, err := io.ReadAll(tlsConn)
    if err != nil {
        log.Fatalf("Failed to read response: %v", err)
    }

    //fmt.Printf("%+v\n", conn)
    return response
}

func main() {
    //Hard coded for now but obv you could get them dynamically
    port := 6443 //CHANGEME
    host := "10.10.10.10" //CHANGEME
    path := "/api/v1/" //CHANGEME
    token, _ := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
    body := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s:%d\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n", path, host, port, string(token))

    response := httpsGetTFO(host, port, path, body)
    fmt.Printf("\n%d bytes recieved:\n\n%s\n", len(response), string(response))
}
