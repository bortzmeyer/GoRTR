/* This package implements the RTR protocol (Router to RPKI cache
protocol) specified in RFC 6810. It is an implementation of the
client, and mostly done for surveys or monitoring, not to be included
in a real router.

Example of use:
        func display(event rtr.Event, state rtr.Client) {
                if event.NewPrefix != nil {
                    fmt.Printf("Got %s\n", even.NewPrefix.Address)
                }
        }

        rtrClient := &rtr.Client{}
	err := rtrClient.Dial("rtr-test.bbn.com:12712", display)
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
	pROTOCOLVERSION = 0
	// PDU types http://www.iana.org/assignments/rpki/rpki.xml#rpki-rtr-pdu
	sERIALNOTIFY  = 0
	sERIALQUERY   = 1
	rESETQUERY    = 2
	cACHERESPONSE = 3
	iPv4PREFIX    = 4
	// 5 not assigned
	iPv6PREFIX = 6
	eNDOFDATA  = 7
	cACHERESET = 8
	// 9 not assigned
	eRRORREPORT = 10
	// Sizes
	hEADERSIZE      = 8
	sERIALQUERYSIZE = 12
	rESETQUERYSIZE  = 8
	mAXSIZE         = 65536
	// Misc
	sLEEPTIME = 40 * time.Minute // The RFC says it must be < 1 hour but some RPKI caches reply with timeout if you don't poll them every five minutes :-(
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

func (client *Client) readData(comm chan error, action func(Event, Client)) (err error) {
	headerbuffer := make([]byte, hEADERSIZE)
	buffer := make([]byte, 1)
	for over := false; !over; {
		n, err := client.connection.Read(headerbuffer)
		if err != nil {
			comm <- errors.New(fmt.Sprintf("Error in TCP Read of header: %s\n", err))
			break
		}
		if headerbuffer[0] != pROTOCOLVERSION {
			comm <- errors.New(fmt.Sprintf("Invalid protocol %d\n", headerbuffer[0]))
			break
		}
		pduType := headerbuffer[1]
		length := int(binary.BigEndian.Uint32(headerbuffer[4:8]))
		if length-hEADERSIZE > 0 {
			buffer = make([]byte, length-hEADERSIZE)
			// TODO: test the length depending on the PDU type?
			for total := 0; total < length-hEADERSIZE; {
				n, err = client.connection.Read(buffer[total:])
				if err != nil {
					comm <- errors.New(fmt.Sprintf("Error in TCP Read of data: %s\n", err))
					break
				}
				total += n
			}
			// TODO: test we had data, for the PDU which require it
		}
		switch pduType {
		case sERIALNOTIFY:
			sessionID := binary.BigEndian.Uint16(headerbuffer[2:4])
			if client.SessionID != nil {
				if *client.SessionID != sessionID {
					comm <- errors.New(fmt.Sprintf("Serial Notify received with a wrong session ID (%d, expecting %d)", sessionID, *client.SessionID))
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
			flags := (buffer[0] & 0x1)
			if length != 20 {
				action(Event{(fmt.Sprintf("IPv4 prefix but with a length != 20: %d bytes (skipped)", length)), nil}, *client)
				continue
			}
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
			flags := (buffer[0] & 0x1)
			if length != 32 {
				action(Event{(fmt.Sprintf("IPv6 prefix but with a length != 32: %d bytes (skipped)", length)), nil}, *client)
				continue
			}
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
			// TODO: test the session ID
			if client.SerialNo == nil {
				client.SerialNo = new(uint32)
			}
			*client.SerialNo = binary.BigEndian.Uint32(buffer[0:4])
			// Then, just wait the next read
			action(Event{"(Temporary) End of Data", nil}, *client)
			// TODO: for the next read, check the session ID ?
		case cACHERESET:
			// The cache probably restarted or lost its history. Let's restart from the bgeinning
			action(Event{"Cache reset", nil}, *client)
			client.resetQuery()
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
	serialquery[0] = pROTOCOLVERSION
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
	resetquery[0] = pROTOCOLVERSION
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
func (client *Client) Dial(address string, action func(Event, Client)) (err error) {
	client.SessionID = nil
	client.SerialNo = nil
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
