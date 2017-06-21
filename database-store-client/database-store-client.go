package main

import (
	"github.com/bortzmeyer/GoRTR/rtr"
	"database/sql"
	"flag"
	"fmt"
	_ "github.com/bmizerany/pq"
	"os"
)

var (
	remote          string
	database        *sql.DB
	eventInsertion  *sql.Stmt
	prefixInsertion *sql.Stmt
)

func store(event rtr.Event, state rtr.Client) {
	transact, err := database.Begin()
	if err != nil {
		fmt.Printf("Cannot start a transaction: %s\n", err)
		os.Exit(1)
	}
	if event.NewPrefix == nil {
		_, err = eventInsertion.Exec(remote, event.Description, state.SerialNo)
		if err != nil {
			fmt.Printf("Cannot execute event insertion: %s\n", err)
			os.Exit(1)
		}
	} else {
		cidr := fmt.Sprintf("%s/%d", event.NewPrefix.Address, event.NewPrefix.Length)
		_, err = prefixInsertion.Exec(event.NewPrefix.Announcement, cidr, event.NewPrefix.MaxLength, state.SerialNo)
		if err != nil {
			fmt.Printf("Cannot execute prefix insertion: %s\n", err)
			os.Exit(1)
		}
	}
	transact.Commit()
}

func main() {
	var (
		err error
	)
	flag.Parse()
	if flag.NArg() != 2 {
		fmt.Printf("Usage: rtrclient server port\n")
		os.Exit(1)
	}
	server := flag.Arg(0)
	port := flag.Arg(1)
	remote = server + ":" + port
	database, err = sql.Open("postgres", "host=/var/run/postgresql dbname=essais sslmode=disable")
	if err != nil { // Useless, Open never fails https://github.com/bmizerany/pq/issues/63
		fmt.Printf("Cannot connnect to PostgreSQL: %s\n", err)
		os.Exit(1)
	}
	_, err = database.Query("SELECT true")
	if err != nil {
		fmt.Printf("Cannot run test query: %s\n", err)
		os.Exit(1)
	}
	eventInsertion, err = database.Prepare("INSERT INTO Events (time, server, event, serialno) VALUES (now(), $1, $2, $3)")
	if err != nil {
		fmt.Printf("Cannot prepare event insertion: %s\n", err)
		os.Exit(1)
	}
	prefixInsertion, err = database.Prepare("INSERT INTO Prefixes (time, announce, prefix, maxlength, serialno) VALUES (now(), $1, $2, $3, $4)")
	if err != nil {
		fmt.Printf("Cannot prepare prefix insertion: %s\n", err)
		os.Exit(1)
	}
	rtrClient := &rtr.Client{}
	err = rtrClient.Dial(remote, store)
	if err != nil {
		fmt.Printf("Problem with RTR server: %s\n", err)
		os.Exit(1)
	}
}
