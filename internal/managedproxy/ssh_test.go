package managedproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"os"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// testSSHKey returns a throwaway PKCS#8 key the core can parse; no real host is used.
func testSSHKey(t *testing.T) string {
	key, _ := testSSHKeyPair(t)
	return key
}

// testSSHKeyPair also returns the public key in authorized_keys form for host-key.
func testSSHKeyPair(t *testing.T) (string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	wire := func(b []byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) }
	authorized := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(append(wire([]byte("ssh-ed25519")), wire(public)...))
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), authorized
}

func TestSSHNodesImportWithInlineKeyOrPassword(t *testing.T) {
	profile := t.TempDir()
	s, _ := Load(profile)
	key, hostKey := testSSHKeyPair(t)
	data := `proxies:
 - {name: vps-key, type: ssh, server: 203.0.113.10, port: 22, username: root, private-key: ` + strconv.Quote(key) + `, host-key: [` + strconv.Quote(hostKey) + `], udp: true}
 - {name: vps-password, type: ssh, server: 203.0.113.11, port: 2222, username: admin, password: test-password, dialer-proxy: vps-key}
`
	if err := s.Import("vps", "", []byte(data), "vps", 0, ""); err != nil {
		t.Fatal(err)
	}
	if s.Count() != 2 {
		t.Fatalf("imported %d SSH nodes, want 2", s.Count())
	}
	keyNode, passwordNode := s.Sources[0].Nodes[0], s.Sources[0].Nodes[1]
	if keyNode.Type != "ssh" || keyNode.Config["private-key"] != key || keyNode.Config["udp"] != false {
		t.Fatal("inline SSH private key was not preserved as TCP-only node")
	}
	if passwordNode.Config["password"] != "test-password" || passwordNode.Config["dialer-proxy"] != keyNode.ID {
		t.Fatal("password SSH node or its transit hop changed during import")
	}
	s.Selected = passwordNode.ID
	if err := s.Save(profile); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(profile)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := loaded.Runtime(profile)
	if err != nil {
		t.Fatal(err)
	}
	var config struct{ Proxies []map[string]any }
	if err := yaml.Unmarshal(runtime, &config); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range config.Proxies {
		if p["type"] == "ssh" && p["private-key"] == key {
			found = true
		}
	}
	if !found {
		t.Fatal("runtime lost the inline SSH private key")
	}
	if os.Getenv("CAGE_PROXY_INTEGRATION") == "1" {
		if err := Validate(context.Background(), profile, loaded); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSSHPrivateKeyFilesAndLocalOptionsAreRejected(t *testing.T) {
	key := testSSHKey(t)
	for _, fields := range []string{
		`private-key: ~/.ssh/id_rsa`,
		`private-key: /etc/ssh/ssh_host_ed25519_key`,
		`Private_Key: /root/.ssh/id_ed25519`,
		`private-key: id_rsa`,
		`private-key: {path: /root/.ssh/id_rsa}`,
		`private-key: ` + strconv.Quote(key) + `, PRIVATE-KEY: ` + strconv.Quote(key),
		`private-key: ` + strconv.Quote(key) + `, interface-name: en0`,
		`private-key: ` + strconv.Quote(key) + `, routing-mark: 255`,
		`password: secret, private-key-path: /root/.ssh/id_rsa`,
	} {
		s, _ := Load(t.TempDir())
		data := `proxies:
 - {name: good, type: http, server: 127.0.0.1, port: 8080}
 - {name: bad, type: ssh, server: 203.0.113.10, port: 22, username: root, ` + fields + `}
`
		if err := s.Import("test", "", []byte(data), "test", 0, ""); err != nil || s.Count() != 1 {
			t.Fatalf("fields %q: count=%d err=%v", fields, s.Count(), err)
		}
		report, _ := json.Marshal(s.Sources[0])
		for _, secret := range []string{"/root/.ssh", "/etc/ssh", "PRIVATE KEY", "secret"} {
			if strings.Contains(string(report), secret) {
				t.Fatalf("fields %q: import diagnosis leaked a field value", fields)
			}
		}
	}
}

func TestInlinePrivateKeyStaysRejectedOutsideSSHNodes(t *testing.T) {
	key := strconv.Quote(testSSHKey(t))
	for _, nodes := range []string{
		`proxies: [{name: test, type: http, server: example.com, port: 80, private-key: ` + key + `}]`,
		`proxies: [{name: test, type: socks5, server: example.com, port: 1080, ws-opts: {private-key: ` + key + `}}]`,
		`proxies: [{name: test, type: ssh, server: example.com, port: 22, username: root, password: x, ws-opts: {private-key: ` + key + `}}]`,
	} {
		if _, err := Parse([]byte(nodes), "test"); err == nil {
			t.Fatalf("private-key accepted outside an SSH node's top level: %s", nodes)
		}
	}
}
