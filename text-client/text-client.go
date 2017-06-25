package main

import (
	"flag"
	"fmt"
	"github.com/bortzmeyer/GoRTR/rtr"
	"os"
	"strconv"
	"time"
)

func display(event rtr.Event, state rtr.Client) {
	var (
		announce    string
		lengthRange string
	)
	currentTime := time.Now().Format(time.RFC3339)
	serial := "unknown"
	if state.SerialNo != nil {
		serial = fmt.Sprintf("%d", *state.SerialNo)
	}
	if event.NewPrefix == nil {
		fmt.Printf("%s %s (#%s)\n", currentTime, event.Description, serial)
	} else {
		if event.NewPrefix.Announcement {
			announce = "PFX ANNOUNCE"
		} else {
			announce = "PFX WITHDRAW"
		}
		if event.NewPrefix.Length == event.NewPrefix.MaxLength {
			lengthRange = fmt.Sprintf("%d", event.NewPrefix.Length)
		} else {
			lengthRange = fmt.Sprintf("%d-%d", event.NewPrefix.Length, event.NewPrefix.MaxLength)
		}
		fmt.Printf("%s %s %s/%s from AS %d (serial #%s)\n", currentTime, announce, event.NewPrefix.Address, lengthRange, event.NewPrefix.ASn, serial)
	}
}

func main() {
	var (
		err error
	)
	version := 1
	flag.Parse()
	if flag.NArg() != 2 && flag.NArg() != 3 {
		fmt.Printf("Usage: rtrclient server port [version]\n")
		os.Exit(1)
	}
	server := flag.Arg(0)
	port := flag.Arg(1)
	remote := server + ":" + port /* TODO does it work with IPv6 ? */
	if flag.NArg() == 3 {
		version, err = strconv.Atoi(flag.Arg(2))
		if err != nil {
			fmt.Printf("RTR version (you typed \"%s\") must be an integer: %s\n", flag.Arg(2), err)
			os.Exit(1)
		}
	}
	rtrClient := &rtr.Client{}
	err = rtrClient.Dial(remote, display, version)
	if err != nil {
		fmt.Printf("%s Problem with RTR server: %s\n", time.Now().Format(time.RFC3339), err)
		os.Exit(1)
	}
}
