package banner

import (
	"slices"
	"strings"
	"testing"
)

func TestIdentify(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		port       int
		raw        string
		tlsDetails *Tls
		expect     string
	}{
		{name: "ssh greeting", port: 22, raw: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n", expect: "ssh"},
		{name: "ssh on an odd port", port: 2222, raw: "SSH-2.0-dropbear_2020.81\r\n", expect: "ssh"},
		{name: "http response", port: 80, raw: "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n", expect: "http"},
		{name: "http on an odd port", port: 8081, raw: "HTTP/1.0 404 Not Found\r\n\r\n", expect: "http"},
		{
			name:   "smtp greeting names itself",
			port:   25,
			raw:    "220 mail.example.com ESMTP Postfix (Debian/GNU)\r\n",
			expect: "smtp",
		},
		{
			name:   "ftp greeting names itself",
			port:   21,
			raw:    "220 (vsFTPd 3.0.3)\r\n",
			expect: "ftp",
		},
		{
			name:   "a bare 220 falls to ftp",
			port:   21,
			raw:    "220 Welcome\r\n",
			expect: "ftp",
		},
		{name: "pop3", port: 110, raw: "+OK POP3 ready\r\n", expect: "pop3"},
		{name: "imap", port: 143, raw: "* OK [CAPABILITY IMAP4rev1] ready\r\n", expect: "imap"},
		{name: "vnc", port: 5900, raw: "RFB 003.008\n", expect: "vnc"},
		{name: "redis", port: 6379, raw: "-ERR unknown command 'GET'\r\n", expect: "redis"},
		{name: "memcached", port: 11211, raw: "ERROR\r\n", expect: "memcached"},
		{
			name:   "mysql handshake",
			port:   3306,
			raw:    "\x4a\x00\x00\x00\x0a" + "8.0.32" + "\x00",
			expect: "mysql",
		},
		{
			name:   "telnet negotiation",
			port:   23,
			raw:    "\xff\xfd\x18\xff\xfd\x20",
			expect: "telnet",
		},
		{
			name:   "an unrecognised banner falls back to the port",
			port:   5432,
			raw:    "\x00\x00\x00\x08\x04\xd2\x16\x2f",
			expect: "postgresql",
		},
		{
			name:   "no banner at all falls back to the port",
			port:   3389,
			raw:    "",
			expect: "rdp",
		},
		{
			name:   "no banner and an unknown port names nothing",
			port:   47123,
			raw:    "",
			expect: "",
		},
		{
			name:       "a tls handshake on 993 is imaps",
			port:       993,
			raw:        "",
			tlsDetails: &Tls{Version: "TLS 1.3"},
			expect:     "imaps",
		},
		{
			name:       "a tls handshake on an odd port is tls",
			port:       44301,
			raw:        "",
			tlsDetails: &Tls{Version: "TLS 1.3"},
			expect:     "tls",
		},
		{
			name:       "http read through tls on 443 is https",
			port:       443,
			raw:        "HTTP/1.1 200 OK\r\n\r\n",
			tlsDetails: &Tls{Version: "TLS 1.3"},
			expect:     "https",
		},
		{
			name:       "http read through tls on an odd port is https",
			port:       44301,
			raw:        "HTTP/1.1 200 OK\r\n\r\n",
			tlsDetails: &Tls{Version: "TLS 1.3"},
			expect:     "https",
		},
		{
			name:       "smtp read through tls on 465 is smtps",
			port:       465,
			raw:        "220 mail.example.com ESMTP Postfix\r\n",
			tlsDetails: &Tls{Version: "TLS 1.2"},
			expect:     "smtps",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := identify(testCase.port, []byte(testCase.raw), testCase.tlsDetails)
			if got != testCase.expect {
				t.Errorf("identify() = %q, want %q", got, testCase.expect)
			}
		})
	}
}

// TestIdentifyPrefersTheBannerOverThePort is the rule the port table exists to lose to: a port
// number is a convention and a banner is evidence.
func TestIdentifyPrefersTheBannerOverThePort(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		port   int
		raw    string
		expect string
	}{
		{name: "ssh on the http port", port: 80, raw: "SSH-2.0-OpenSSH_9.0\r\n", expect: "ssh"},
		{name: "http on the ssh port", port: 22, raw: "HTTP/1.1 400 Bad Request\r\n", expect: "http"},
		{name: "redis on the mysql port", port: 3306, raw: "-ERR unknown command\r\n", expect: "redis"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := identify(testCase.port, []byte(testCase.raw), nil)
			if got != testCase.expect {
				t.Errorf("identify() = %q, want %q -- the port table won over the banner", got, testCase.expect)
			}
		})
	}
}

func TestText(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		raw    string
		expect string
	}{
		{name: "empty", raw: "", expect: ""},
		{
			name:   "a greeting loses its line ending",
			raw:    "SSH-2.0-OpenSSH_8.9p1\r\n",
			expect: "SSH-2.0-OpenSSH_8.9p1",
		},
		{
			name:   "multiple lines collapse to one",
			raw:    "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
			expect: "HTTP/1.1 200 OK Server: nginx",
		},
		{
			name:   "runs of whitespace collapse",
			raw:    "220    mail  \t ready\r\n",
			expect: "220 mail ready",
		},
		{
			name:   "an escape sequence ends the run around it, and a short remnant is dropped",
			raw:    "\x1b[31mred\x1b[0m",
			expect: "[31mred",
		},
		{
			name:   "a short text greeting survives whole",
			raw:    "+OK\r\n",
			expect: "+OK",
		},
		{
			name:   "a short text greeting with a code survives whole",
			raw:    "* OK\r\n",
			expect: "* OK",
		},
		{
			name:   "a version string is recovered from a binary handshake, the stray byte around it is not",
			raw:    "\x4a\x00\x00\x00\x0a8.0.32\x00",
			expect: "8.0.32",
		},
		{
			name:   "bytes outside ascii make a short blob binary, and its short runs are dropped",
			raw:    "alpha\xff\xfe\xfdbeta",
			expect: "",
		},
		{
			name:   "a version string is kept out of a binary blob that is mostly noise",
			raw:    "\x00\x8f\xff\x01Apache/2.4.7\x00\xfe\x9c\x00\x11",
			expect: "Apache/2.4.7",
		},
		{
			name:   "non-ascii inside otherwise textual output is dropped, not transliterated",
			raw:    "Server: caf\xc3\xa9-httpd/1.0 ready\r\n",
			expect: "Server: caf -httpd/1.0 ready",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := text([]byte(testCase.raw))
			if got != testCase.expect {
				t.Errorf("text() = %q, want %q", got, testCase.expect)
			}
		})
	}
}

// TestTextIsBounded is the property that matters for everything downstream: a banner is arbitrary
// bytes from a stranger, and it ends up in a database column and a PDF.
func TestTextIsBounded(t *testing.T) {
	t.Parallel()

	rendered := text([]byte(strings.Repeat("a", 10*maxTextLength)))

	if len(rendered) > maxTextLength {
		t.Errorf("text() returned %d bytes, want at most %d", len(rendered), maxTextLength)
	}
}

func TestTextIsPrintable(t *testing.T) {
	t.Parallel()

	raw := make([]byte, 256)
	for index := range raw {
		raw[index] = byte(index)
	}

	for _, character := range text(raw) {
		if character < 0x20 || character > 0x7e {
			t.Errorf("text() kept the non-ASCII-printable character %q", character)
		}
	}
}

// TestTextDropsBinaryNoise is what keeps a binary protocol's greeting from being reported as though
// the service had said something. Random bytes contain printable ASCII by chance -- about a third
// of byte values are -- and rendering those is how a handshake comes out as gibberish.
func TestTextDropsBinaryNoise(t *testing.T) {
	t.Parallel()

	// A fixed pseudo-random stream, so the test says the same thing on every run.
	raw := make([]byte, 4096)
	state := uint32(1)
	for index := range raw {
		state = state*1664525 + 1013904223
		raw[index] = byte(state >> 24)
	}

	rendered := text(raw)

	// Some runs of four printable characters will occur by chance in four kilobytes; the point is
	// that what survives is a fraction of it rather than a line of mojibake.
	if len(rendered) > len(raw)/32 {
		t.Errorf("text() kept %d characters of %d random bytes: %q", len(rendered), len(raw), rendered)
	}

	for _, character := range rendered {
		if character < 0x20 || character > 0x7e {
			t.Errorf("text() kept the non-ASCII-printable character %q", character)
		}
	}
}

func TestIsTlsPort(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		port   int
		expect bool
	}{
		{name: "https", port: 443, expect: true},
		{name: "imaps", port: 993, expect: true},
		{name: "smtps", port: 465, expect: true},
		{name: "http is not", port: 80, expect: false},
		{name: "ssh is not", port: 22, expect: false},
		{name: "submission is not, it starts in the clear", port: 587, expect: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := isTlsPort(testCase.port); got != testCase.expect {
				t.Errorf("isTlsPort(%d) = %v, want %v", testCase.port, got, testCase.expect)
			}
		})
	}
}

// TestTlsPortsAllHaveNames keeps the two tables in step: isTlsPort is derived from
// tlsPortServices, so a port added to one is a port added to the other.
func TestTlsPortsAllHaveNames(t *testing.T) {
	t.Parallel()

	for port, service := range tlsPortServices {
		if service == "" {
			t.Errorf("port %d is listed as a TLS port with no service name", port)
		}
		if !isTlsPort(port) {
			t.Errorf("port %d has a TLS service name but is not a TLS port", port)
		}
	}
}

// TestSignaturesAreOrdered guards the one ordering that is load-bearing: the bare "220" catch-all
// has to come after the checks that read what follows it, or every SMTP server is called FTP.
func TestSignaturesAreOrdered(t *testing.T) {
	t.Parallel()

	bareGreeting := slices.IndexFunc(signatures, func(candidate *signature) bool {
		return candidate.service == "ftp" && candidate.matches([]byte("220 Welcome\r\n"))
	})
	smtpGreeting := slices.IndexFunc(signatures, func(candidate *signature) bool {
		return candidate.service == "smtp"
	})

	if bareGreeting < 0 || smtpGreeting < 0 {
		t.Fatalf("expected both a bare-220 and an SMTP signature, got %d and %d", bareGreeting, smtpGreeting)
	}

	if bareGreeting < smtpGreeting {
		t.Error("the bare 220 signature precedes the SMTP one, so every SMTP greeting is read as FTP")
	}
}
