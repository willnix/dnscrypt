package dnscrypt

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
)

var (
	certificateMagic = "DNSC"
	resolverMagic    = [8]byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}
	dnsMaxSizeUDP    = 65536 - 20 - 8
)

// GetValidCert retrieves th DNSC certificate for a server
// it validates the certificate and returns the certificates details
// iff it is valid. Otherwise an error is returned.
func GetValidCert(serverAddress string, providerName string, providerKey []byte) (SignedBincertFields, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(providerName), dns.TypeTXT)

	in, err := dns.Exchange(m, serverAddress)
	if err != nil {
		return SignedBincertFields{}, err
	}

	if len(in.Answer) == 0 {
		return SignedBincertFields{}, errors.New("No answer to pubkey DNS request")
	}

	var bincert *signedBincert
	for _, answer := range in.Answer {
		t, ok := answer.(*dns.TXT)
		if !ok {
			return SignedBincertFields{}, errors.New("First answer not a TXT record")
		}

		// check for magic Bytes
		if t.Txt[0][0:5] == certificateMagic {
			return SignedBincertFields{}, errors.New("TXT record is not a DNSC certificate")
		}

		// decode weird TXT record representation
		unpackedBinCert, err := unpackTXT([]byte(t.Txt[0]))
		if err != nil {
			return SignedBincertFields{}, err
		}

		// parse outer structure for signature verification
		buf := bytes.NewReader(unpackedBinCert)
		bincert = new(signedBincert)
		err = binary.Read(buf, binary.BigEndian, bincert)
		if err != nil {
			return SignedBincertFields{}, err
		}

		// Version indicates which crypto construction to use
		// For X25519-XSalsa20Poly1305, <es-version> must be 0x00 0x01.
		// For X25519-XChacha20Poly1305, <es-version> must be 0x00 0x02.
		if bincert.VersionMajor != 0x01 {
			// we do not support this version, look further
			bincert = nil
			continue
		}
	}
	// have we found a supported certificate?
	if bincert == nil {
		return SignedBincertFields{}, errors.New("No certificate for supported crypto constructions found")
	}

	// check signature
	valid := ed25519.Verify(providerKey, bincert.SignedData[:], bincert.Signature[:])
	if !valid {
		return SignedBincertFields{}, errors.New("Invalid certificate Signature")
	}

	// parse inner structure to get pubkey, validity dates, etc.
	buf := bytes.NewReader(bincert.SignedData[:])
	bincertFields := SignedBincertFields{}
	err = binary.Read(buf, binary.BigEndian, &bincertFields)
	if err != nil {
		return SignedBincertFields{}, err
	}

	// is the certificate valid?
	// get unsigned timestamp while avoiding uint wrap-arounds
	var now uint64
	if nowSigned := time.Now().Unix(); nowSigned >= 0 {
		now = uint64(nowSigned)
	} else {
		return SignedBincertFields{}, errors.New("Time traveler alert! Certificates can only be valid from 1970 onwards.")
	}
	// compare with timestamps in cert
	// uint32 -> uint64 should be safe
	if now < uint64(bincertFields.TSBegin) {
		return SignedBincertFields{}, errors.New("Certificate is not yet valid")
	} else if now > uint64(bincertFields.TSEnd) {
		return SignedBincertFields{}, errors.New("Certificate is no longer valid")
	}

	return bincertFields, nil
}

// ExchangeEncrypted exchanges encrypted dns query and returns the response message.
// It needs the specifics of a DNSC server as obtained by calling GetValidCert()
func ExchangeEncrypted(serverAddress string, msg dns.Msg, bincertFields SignedBincertFields) (dns.Msg, error) {
	// TODO: the following will be wrapped in a lookUP() function
	queryHeader := dnsCryptQueryHeader{
		ClientMagic: bincertFields.MagicQuery,
	}
	// Client Nonce
	// The specification says half of the nonce should be zeros => ClientNonce[:12]
	if _, err := rand.Read(queryHeader.ClientNonce[:12]); err != nil {
		return dns.Msg{}, err
	}
	// KeyPair
	clientPK, clientSK, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return dns.Msg{}, err
	}
	queryHeader.ClientPublicKey = *clientPK

	serializedDNSQuery, err := msg.PackBuffer(nil)
	if err != nil {
		return dns.Msg{}, err
	}

	// add padding
	serializedDNSQuery, err = addPadding(serializedDNSQuery)
	if err != nil {
		return dns.Msg{}, err
	}

	// build nonce: <nonce> := <client_nonce><12 zeros>
	var nonce [24]byte
	copy(nonce[:], append(queryHeader.ClientNonce[:12], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...))
	// we use nacl.box authenticetd encryption for the query
	encryptedQuery := box.Seal(nil, serializedDNSQuery, &nonce, &bincertFields.ServerPublicKey, clientSK)

	// serialize header and encrypted query to buffer
	dnscryptQuery := new(bytes.Buffer)
	binary.Write(dnscryptQuery, binary.BigEndian, queryHeader)
	binary.Write(dnscryptQuery, binary.BigEndian, encryptedQuery)

	conn, err := net.Dial("udp", serverAddress)
	if err != nil {
		return dns.Msg{}, err
	}
	// send query
	binary.Write(conn, binary.BigEndian, dnscryptQuery.Bytes())

	///////////////////////////////////////////////////////////////////////////////////////
	// DONE SENDING
	///////////////////////////////////////////////////////////////////////////////////////

	// receive
	p := make([]byte, dnsMaxSizeUDP)
	n, err := bufio.NewReader(conn).Read(p)
	if err != nil {
		return dns.Msg{}, err
	}

	// parse response header
	responseHeaderBytes := bytes.NewBuffer(p[:32])
	var responseHeader dnsCryptResponseHeader
	err = binary.Read(responseHeaderBytes, binary.BigEndian, &responseHeader)
	if err != nil {
		return dns.Msg{}, err
	}

	// check magic bytes
	if responseHeader.ServerMagic != resolverMagic {
		return dns.Msg{}, errors.New("Magic bytes do not match")
	}

	// encrypted reply
	encryptedResponse := p[32:n]

	// decrypt the reply with info from the header
	copy(nonce[:], append(responseHeader.ClientNonce[:], responseHeader.ServerNonce[:]...))
	dnsResponse, ok := box.Open(nil, encryptedResponse, &nonce, &bincertFields.ServerPublicKey, clientSK)
	if !ok {
		return dns.Msg{}, errors.New("Could not decrypt response")
	}

	// strip padding from the decrypted dns response
	dnsResponse, err = removePadding(dnsResponse)
	if err != nil {
		return dns.Msg{}, err
	}

	// parse dns response
	responseMsg := new(dns.Msg)
	err = responseMsg.Unpack(dnsResponse)
	if err != nil {
		return dns.Msg{}, err
	}

	return *responseMsg, nil
}
