package main

import (
	"./rtr"
	"flag"
	"fmt"
	"os"
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
		fmt.Printf("%s %s %s/%s from %d (#%s)\n", currentTime, announce, event.NewPrefix.Address, lengthRange, event.NewPrefix.ASn, serial)
	}
}

func main() {
	flag.Parse()
	if flag.NArg() != 2 {
		fmt.Printf("Usage: rtrclient server port\n")
		os.Exit(1)
	}
	server := flag.Arg(0)
	port := flag.Arg(1)
	remote := server + ":" + port
	rtrClient := &rtr.Client{}
	err := rtrClient.Dial(remote, display)
	if err != nil {
		fmt.Printf("%s Problem with RTR server: %s\n", time.Now().Format(time.RFC3339), err)
		os.Exit(1)
	}
}
