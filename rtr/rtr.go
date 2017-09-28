/* This package implements the RTR protocol (Router to RPKI cache
protocol) specified in RFC 6810 and 8210. It is an implementation of
the client, and mostly done for surveys or monitoring, not to be
included in a real router.

Example of use:
        func display(event rtr.Event, state rtr.Client) {
                if event.NewPrefix != nil {
                    fmt.Printf("Got %s\n", even.NewPrefix.Address)
                }
        }

        rtrClient := &rtr.Client{}
	err := rtrClient.Dial("rpki-validator.realmv6.org:8282", display, 0)
	if err != nil {
		fmt.Printf("Problem with RTR server: %s\n", err)
		os.Exit(1)
	}

Released under a 2-clause BSD license (or simplified BSD license; it
is equivalent to the ISC license). Basically, do what you want with
it.

Stephane Bortzmeyer <bortzmeyer@nic.fr>
*/
package rtr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	// PDU types http://www.iana.org/assignments/rpki/rpki.xml#rpki-rtr-pdu
	sERIALNOTIFY  = 0
	sERIALQUERY   = 1
	rESETQUERY    = 2
	cACHERESPONSE = 3
	iPv4PREFIX    = 4
	// 5 not assigned
	iPv6PREFIX  = 6
	eNDOFDATA   = 7
	cACHERESET  = 8
	rOUTERKEY   = 9
	eRRORREPORT = 10
	// Sizes
	hEADERSIZE      = 8
	sERIALQUERYSIZE = 12
	rESETQUERYSIZE  = 8
	mAXSIZE         = 65536
	// Misc
	sLEEPTIME = 40 * time.Minute // The RFC says it must be < 1 hour but some RPKI caches reply with timeout if you don't poll them every five minutes :-(
)

var (
	protocolVersion byte
	debug           bool = false // TODO export it for the clients
)

// A connection to the validating RPKI cache (RFC 6480)
type Client struct {
	connection net.Conn
	SessionID  *uint16
	SerialNo   *uint32
}

// A ROA (RFC 6482) prefix (IPv4 or IPv6)
type Prefix struct {
	Announcement bool
	Address      net.IP
	Length       uint8
	MaxLength    uint8
	ASn          uint32
}

// An interesting event from the cache, typically a new prefix
type Event struct {
	Description string
	NewPrefix   *Prefix // nil if if the event is not a new prefix
}

func checkLength(comm chan error, ptype byte, length uint, expected uint) (err error) {
	if length != expected {
		err := errors.New(fmt.Sprintf("For packet type %d, expected a legth of %d, but got %d\n", ptype, expected, length))
		comm <- err
	}
	return err
}

func (client *Client) readData(comm chan error, action func(Event, Client)) (err error) {
	var (
		buffer []byte
		total  uint
		n      int
	)
	headerbuffer := make([]byte, hEADERSIZE)
	for over := false; !over; {
		for total = 0; total < hEADERSIZE; { // TODO add a timeout, if the TCP session becomes stale?
			n, err = client.connection.Read(headerbuffer[total:])
			if err != nil {
				comm <- errors.New(fmt.Sprintf("Error in TCP Read of RTR header: \"%s\" (got %d bytes)\n", err, n))
				break
			}
			total += uint(n)
		}
		if total < hEADERSIZE {
			comm <- errors.New(fmt.Sprintf("Short in TCP Read of RTR header: got %d bytes, expected %d\n", total, hEADERSIZE))
			break
		}
		if headerbuffer[0] != protocolVersion {
			comm <- errors.New(fmt.Sprintf("Invalid protocol %d\n", headerbuffer[0]))
			break
		}
		pduType := headerbuffer[1]
		length := uint(binary.BigEndian.Uint32(headerbuffer[4:8]))
		if length-hEADERSIZE > 0 {
			buffer = make([]byte, length-hEADERSIZE)
			for total = 0; total < length-hEADERSIZE; {
				n, err = client.connection.Read(buffer[total:])
				if err != nil {
					comm <- errors.New(fmt.Sprintf("Error in TCP Read of data: %s\n", err))
					break
				}
				total += uint(n)
			}
			if total < length-hEADERSIZE {
				comm <- errors.New(fmt.Sprintf("Short in TCP Read of data: got %d bytes, expected %d\n", total+hEADERSIZE, length))
				break
			}
		}
		if debug {
			fmt.Printf("DEBUG: PDU %d\n", buffer)
		}
		switch pduType {
		case sERIALNOTIFY:
			err := checkLength(comm, pduType, length, 12)
			if err != nil {
				break
			}
			sessionID := binary.BigEndian.Uint16(headerbuffer[2:4])
			if client.SessionID != nil {
				if *client.SessionID != sessionID {
					comm <- errors.New(fmt.Sprintf("Serial Notify received with a wrong session ID (%d, expecting %d); cache restarted?", sessionID, *client.SessionID))
					break
				}
			} else {
				client.SessionID = new(uint16)
				*client.SessionID = sessionID
			}
			serialNo := binary.BigEndian.Uint32(buffer[0:4])
			action(Event{fmt.Sprintf("Serial Notify #%d -> #%d", *client.SerialNo, serialNo), nil}, *client)
			if client.SerialNo == nil { // Should not happen but let's be robust
				client.resetQuery()
			} else if serialNo != *client.SerialNo {
				client.serialQuery()
			}
		case cACHERESPONSE:
			err := checkLength(comm, pduType, length, 8)
			if err != nil {
				break
			}
			sessionID := binary.BigEndian.Uint16(headerbuffer[2:4])
			if client.SessionID != nil {
				if *client.SessionID != sessionID {
					comm <- errors.New(fmt.Sprintf("Cache Response received with a wrong session ID (%d, expecting %d)", sessionID, *client.SessionID))
					break
				}
			} else {
				client.SessionID = new(uint16)
				*client.SessionID = sessionID
			}
			action(Event{fmt.Sprintf("Cache Response, session is %d", *client.SessionID), nil}, *client)
		case iPv4PREFIX:
			err := checkLength(comm, pduType, length, 20)
			if err != nil {
				break
			}
			flags := (buffer[0] & 0x1)
			announcement := false
			if flags == 1 {
				announcement = true
			}
			plength := buffer[1]
			maxlength := buffer[2]
			asn := binary.BigEndian.Uint32(buffer[8:12])
			prefix := Prefix{announcement, net.IP(buffer[4:8]), plength, maxlength, asn}
			action(Event{"Prefix", &prefix}, *client)
		case iPv6PREFIX:
			err := checkLength(comm, pduType, length, 32)
			if err != nil {
				break
			}
			flags := (buffer[0] & 0x1)
			announcement := false
			if flags == 1 {
				announcement = true
			}
			plength := buffer[1]
			maxlength := buffer[2]
			asn := binary.BigEndian.Uint32(buffer[20:24])
			prefix := Prefix{announcement, net.IP(buffer[4:20]), plength, maxlength, asn}
			action(Event{"Prefix", &prefix}, *client)
		case eNDOFDATA:
			err := checkLength(comm, pduType, length, 12)
			if err != nil {
				break
			}
			// TODO: test the session ID
			if client.SerialNo == nil {
				client.SerialNo = new(uint32)
			}
			*client.SerialNo = binary.BigEndian.Uint32(buffer[0:4])
			// Then, just wait the next read
			action(Event{"(Temporary) End of Data", nil}, *client)
			// TODO: for the next read, check the session ID ?
		case cACHERESET:
			err := checkLength(comm, pduType, length, 8)
			if err != nil {
				break
			}
			// The cache probably restarted or lost its history. Let's restart from the bgeinning
			action(Event{"Cache reset", nil}, *client)
			client.resetQuery()
		case rOUTERKEY:
			if protocolVersion <= 0 {
				comm <- errors.New(fmt.Sprintf("Invalid Router Key message received for protocol version %d", protocolVersion))
				break
			}
			action(Event{"Router Key (ignored)", nil}, *client)
		case eRRORREPORT:
			lengthPDU := binary.BigEndian.Uint32(buffer[0:4])
			lengthText := binary.BigEndian.Uint32(buffer[4+lengthPDU : 8+lengthPDU])
			errorCode := binary.BigEndian.Uint16(headerbuffer[2:4]) // http://www.iana.org/assignments/rpki/rpki.xml#rpki-rtr-error
			errorText := string(buffer[8+lengthPDU : 8+lengthPDU+lengthText])
			comm <- errors.New(fmt.Sprintf("Got an Error Report #%d \"%s\"", errorCode, errorText))
			break
		default:
			comm <- errors.New(fmt.Sprintf("Unknown PDU type %d\n", pduType)) // TODO: what does the RFC says about that?
			break
		}
	}
	return err
}

func (client *Client) serialQuery() (err error) {
	if client.SerialNo == nil {
		return errors.New("serialQuery called but no serial number known")
	}
	serialquery := make([]byte, sERIALQUERYSIZE)
	serialquery[0] = protocolVersion
	serialquery[1] = sERIALQUERY
	binary.BigEndian.PutUint16(serialquery[2:4], *client.SessionID)
	binary.BigEndian.PutUint32(serialquery[4:8], sERIALQUERYSIZE)
	binary.BigEndian.PutUint32(serialquery[8:12], *client.SerialNo)
	n, err := client.connection.Write(serialquery)
	if n != sERIALQUERYSIZE || err != nil {
		return errors.New("Writing Serial Query failed") // TODO better messages for the two cases
	}
	return err
}

func (client *Client) resetQuery() (err error) {
	resetquery := make([]byte, rESETQUERYSIZE)
	resetquery[0] = protocolVersion
	resetquery[1] = rESETQUERY
	resetquery[2] = 0 // No need to indicate a real Session ID
	resetquery[3] = 0
	binary.BigEndian.PutUint32(resetquery[4:8], rESETQUERYSIZE)
	// TODO: allow to start with Serial Query (and a given serial number)?
	n, err := client.connection.Write(resetquery)
	if n != rESETQUERYSIZE || err != nil {
		return errors.New("Writing Reset Query failed") // TODO better messages for the two cases
	}
	return err
}

func (client *Client) loop() (err error) {
	for over := false; !over; {
		time.Sleep(sLEEPTIME)
		err := client.serialQuery()
		if err != nil {
			return errors.New("Writing Serial Query failed")
		}
	}
	return nil
}

// Connect to a RPKI cache and run the provided callback "action" for
// each prefix we receive. This function will never return except in
// case of error. If you want to continue even when the cache
// restarts, you have to loop over Dial()
func (client *Client) Dial(address string, action func(Event, Client), version int) (err error) {
	client.SessionID = nil
	client.SerialNo = nil
	protocolVersion = byte(version)
	client.connection, err = net.Dial("tcp", address)
	if err != nil {
		return err
	}
	defer client.connection.Close()
	client.resetQuery()
	// TODO: allow to start with Serial Query (and a given serial number)?
	errChannel := make(chan error)
	go client.readData(errChannel, action)
	go client.loop()
	status := <-errChannel
	return status
}
