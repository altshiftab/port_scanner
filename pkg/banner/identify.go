package banner

import (
	"bytes"
	"strings"
)

// The service names that appear in more than one table, named so the two cannot drift apart.
const (
	serviceHttp     = "http"
	serviceHttps    = "https"
	serviceHttpAlt  = "http-alt"
	serviceHttpsAlt = "https-alt"
	serviceRedis    = "redis"
)

// signature names a service by what it says. The checks run in order and the first that matches
// wins, so the specific ones come before the general.
type signature struct {
	service string
	matches func([]byte) bool
}

func hasPrefix(prefix string) func([]byte) bool {
	return func(raw []byte) bool {
		return bytes.HasPrefix(raw, []byte(prefix))
	}
}

// firstLine is what the greeting-based checks look at. A service that says more than a greeting
// should not have its later output mistaken for one.
func firstLine(raw []byte) []byte {
	if index := bytes.IndexAny(raw, "\r\n"); index >= 0 {
		return raw[:index]
	}

	return raw
}

// greetingContains matches a line-oriented greeting that opens with code and mentions any of the
// words. FTP and SMTP both greet with "220", and only the text after it tells them apart.
//
// Given no words it matches on the code alone, which is what makes it usable as the catch-all that
// runs after the checks that read what follows the code.
func greetingContains(code string, words ...string) func([]byte) bool {
	return func(raw []byte) bool {
		line := firstLine(raw)
		if !bytes.HasPrefix(line, []byte(code)) {
			return false
		}

		if len(words) == 0 {
			return true
		}

		upper := strings.ToUpper(string(line))
		for _, word := range words {
			if strings.Contains(upper, word) {
				return true
			}
		}

		return false
	}
}

// isMySql recognises the handshake MySQL and MariaDB open with: a three-byte payload length, a
// sequence number of zero, then the protocol version, which is 10 for everything current.
func isMySql(raw []byte) bool {
	const protocolVersion10 = 0x0a

	if len(raw) < 6 || raw[3] != 0x00 || raw[4] != protocolVersion10 {
		return false
	}

	// The version string follows the protocol byte and is NUL-terminated printable text. Checking
	// it keeps an arbitrary binary stream that happens to start with these bytes from being called
	// MySQL.
	return raw[5] >= '0' && raw[5] <= '9'
}

// isSmb recognises the SMB header, whose four-byte marker sits after a NetBIOS session header.
func isSmb(raw []byte) bool {
	return len(raw) >= 8 &&
		(bytes.Equal(raw[4:8], []byte{0xff, 'S', 'M', 'B'}) ||
			bytes.Equal(raw[4:8], []byte{0xfe, 'S', 'M', 'B'}))
}

// isTelnet recognises the option negotiation a telnet server opens with: IAC followed by one of the
// negotiation verbs.
func isTelnet(raw []byte) bool {
	const interpretAsCommand = 0xff

	if len(raw) < 3 || raw[0] != interpretAsCommand {
		return false
	}

	switch raw[1] {
	case 0xfb, 0xfc, 0xfd, 0xfe: // WILL, WON'T, DO, DON'T
		return true
	default:
		return false
	}
}

// signatures are the services a banner names outright.
var signatures = []*signature{
	{service: "ssh", matches: hasPrefix("SSH-")},
	{service: serviceHttp, matches: hasPrefix("HTTP/")},
	{service: "rtsp", matches: hasPrefix("RTSP/")},
	{service: "sip", matches: hasPrefix("SIP/")},
	{service: "vnc", matches: hasPrefix("RFB ")},
	{service: "amqp", matches: hasPrefix("AMQP")},
	{service: "jdwp", matches: hasPrefix("JDWP-Handshake")},
	{service: "mqtt", matches: hasPrefix("MQTT")},
	// Redis answers an unrecognised greeting with an error, and the error names it.
	{service: serviceRedis, matches: hasPrefix("-ERR")},
	{service: serviceRedis, matches: hasPrefix("-NOAUTH")},
	{service: serviceRedis, matches: hasPrefix("+PONG")},
	// Memcached likewise.
	{service: "memcached", matches: hasPrefix("ERROR\r\n")},
	{service: "ftp", matches: greetingContains("220", "FTP", "FILEZILLA", "PROFTPD", "VSFTPD", "PURE-FTPD")},
	{service: "smtp", matches: greetingContains("220", "SMTP", "ESMTP", "POSTFIX", "EXIM", "SENDMAIL")},
	{service: "nntp", matches: greetingContains("200", "NNTP", "NNRP")},
	{service: "pop3", matches: hasPrefix("+OK")},
	{service: "imap", matches: hasPrefix("* OK")},
	{service: "imap", matches: hasPrefix("* PREAUTH")},
	{service: "irc", matches: hasPrefix(":")},
	{service: "mysql", matches: isMySql},
	{service: "smb", matches: isSmb},
	{service: "telnet", matches: isTelnet},
	// Last of the greeting checks: a bare 220 that named nothing is far more often FTP than not.
	{service: "ftp", matches: greetingContains("220")},
}

// portServices names the service conventionally found on a port. It is the fallback for a port that
// gave nothing away, so it is a guess and the caller should treat it as one: it says what usually
// listens there, not what answered.
var portServices = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    serviceHttp,
	110:   "pop3",
	111:   "rpcbind",
	135:   "msrpc",
	139:   "netbios-ssn",
	143:   "imap",
	161:   "snmp",
	389:   "ldap",
	443:   serviceHttps,
	445:   "smb",
	465:   "smtps",
	514:   "syslog",
	515:   "printer",
	587:   "submission",
	623:   "ipmi",
	631:   "ipp",
	636:   "ldaps",
	873:   "rsync",
	990:   "ftps",
	993:   "imaps",
	995:   "pop3s",
	1080:  "socks",
	1433:  "mssql",
	1521:  "oracle",
	1883:  "mqtt",
	2049:  "nfs",
	2375:  "docker",
	2376:  "docker-tls",
	3000:  serviceHttpAlt,
	3306:  "mysql",
	3389:  "rdp",
	4444:  serviceHttpAlt,
	5060:  "sip",
	5432:  "postgresql",
	5601:  "kibana",
	5672:  "amqp",
	5900:  "vnc",
	5985:  "winrm",
	5986:  "winrm-tls",
	6379:  serviceRedis,
	7001:  "weblogic",
	8000:  serviceHttpAlt,
	8008:  serviceHttpAlt,
	8080:  "http-proxy",
	8086:  "influxdb",
	8443:  serviceHttpsAlt,
	8888:  serviceHttpAlt,
	9000:  serviceHttpAlt,
	9092:  "kafka",
	9200:  "elasticsearch",
	9300:  "elasticsearch",
	11211: "memcached",
	15672: "rabbitmq",
	27017: "mongodb",
	27018: "mongodb",
	50000: "db2",
}

// tlsPortServices names what a port speaks once its TLS layer is peeled away. A TLS handshake on
// 993 says the port is IMAP over TLS, which is more than "tls" and more than "imap".
var tlsPortServices = map[int]string{
	443:   serviceHttps,
	465:   "smtps",
	563:   "nntps",
	636:   "ldaps",
	990:   "ftps",
	993:   "imaps",
	995:   "pop3s",
	2376:  "docker-tls",
	5986:  "winrm-tls",
	8443:  serviceHttpsAlt,
	9443:  serviceHttpsAlt,
	10250: "kubelet",
}

// tlsPorts are the ports a grab tries TLS on before trying anything else. Every port that has a
// name for its TLS form is one, since that name is the evidence it conventionally speaks TLS.
func isTlsPort(port int) bool {
	_, ok := tlsPortServices[port]

	return ok
}

// identify names the service a grab found.
//
// What was said outranks where it was said: a banner that names a service is evidence, and a port
// number is a convention that anything may ignore. So the signatures are consulted first, the port
// table only for a port that gave nothing away.
func identify(port int, raw []byte, tlsDetails *Tls) string {
	if len(raw) > 0 {
		for _, candidate := range signatures {
			if candidate.matches(raw) {
				return withTls(candidate.service, port, tlsDetails)
			}
		}
	}

	if tlsDetails != nil {
		if service, ok := tlsPortServices[port]; ok {
			return service
		}

		return "tls"
	}

	return portServices[port]
}

// withTls adjusts a service named by its banner for having been read through a TLS handshake. HTTP
// read over TLS is HTTPS; the rest are named by their port, or left as they are.
func withTls(service string, port int, tlsDetails *Tls) string {
	if tlsDetails == nil {
		return service
	}

	if service == serviceHttp {
		if named, ok := tlsPortServices[port]; ok {
			return named
		}

		return serviceHttps
	}

	if named, ok := tlsPortServices[port]; ok {
		return named
	}

	return service
}

// maxTextLength is how much of a banner text rendering keeps. A banner worth reading identifies
// itself in its first line; the rest is a login prompt or an HTML page.
const maxTextLength = 512

const (
	// binaryRunLength is how many printable characters have to sit together to be kept out of a
	// banner that is not text.
	//
	// About a third of byte values are printable ASCII, so short runs of them turn up all through a
	// binary greeting by chance; keeping those produces a line of gibberish that reads as though
	// the service had said something. Six is long enough to be rare in noise and short enough for
	// the thing actually worth recovering from a binary handshake, which is a version string.
	binaryRunLength = 6

	// textualThreshold is the share of a banner that has to be printable ASCII or whitespace for it
	// to be treated as text.
	//
	// The distinction is needed because the two kinds of banner want opposite treatment. A text
	// greeting may be very short -- POP3 opens with "+OK" -- so discarding short runs would throw
	// it away; a binary one is mostly noise, so keeping them fills the field with rubbish.
	textualThreshold = 0.85
)

// isTextual reports whether a banner is text rather than a binary protocol's greeting.
func isTextual(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}

	var printable int
	for _, octet := range raw {
		if (octet >= ' ' && octet < 0x7f) || octet == '\t' || octet == '\r' || octet == '\n' {
			printable++
		}
	}

	return float64(printable)/float64(len(raw)) >= textualThreshold
}

// text renders a banner as a single line of printable text, for somebody reading a report rather
// than a packet.
//
// It keeps printable ASCII and nothing else. A banner is arbitrary bytes from a stranger that end
// up in a database column, a JSON document and a PDF, and every protocol that greets in text greets
// in ASCII -- so anything outside it is either binary that decoded as characters by accident or an
// encoding nobody downstream agreed to handle. Interpreting those bytes as UTF-8 and keeping
// whatever happened to be printable is how a binary handshake comes out as a line of mojibake.
func text(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}

	// A banner that is text is kept whole, however short its pieces; one that is not is mined for
	// the stretches long enough to be something rather than coincidence.
	minimumRun := 1
	if !isTextual(raw) {
		minimumRun = binaryRunLength
	}

	var builder strings.Builder
	run := make([]byte, 0, 64)

	// flush keeps the run if it is long enough to be worth keeping, separating it from the last one
	// that was.
	flush := func() {
		trimmed := bytes.TrimRight(run, " ")
		if len(trimmed) >= minimumRun {
			if builder.Len() > 0 {
				builder.WriteByte(' ')
			}
			builder.Write(trimmed)
		}

		run = run[:0]
	}

	for _, octet := range raw {
		if builder.Len() >= maxTextLength {
			break
		}

		switch {
		case octet == ' ' || octet == '\t':
			// Whitespace does not end a run, but a stretch of it collapses to one space, so that a
			// padded or multi-part greeting renders as one line.
			if len(run) > 0 && run[len(run)-1] != ' ' {
				run = append(run, ' ')
			}
		case octet > ' ' && octet < 0x7f:
			run = append(run, octet)
		default:
			// A control byte or anything outside ASCII ends the run: the text either side of it is
			// not one phrase.
			flush()
		}
	}

	flush()

	rendered := builder.String()
	if len(rendered) > maxTextLength {
		rendered = rendered[:maxTextLength]
	}

	return strings.TrimSpace(rendered)
}
