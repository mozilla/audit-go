package main

import (
	"./libaudit-go"
	"log"
	"os"
	"io/ioutil"
	"syscall"
	"encoding/json"
	"time"
)

var done chan bool
var debug bool

func EventCallback(msg *netlinkAudit.AuditEvent, ce chan error, args ...interface{}) {
	// convert to JSON
	jsonString, err := json.Marshal(msg.Data)
	if err != nil {
		log.Println(err)
	} else {
		log.Println("Type="+msg.Type +" Info="+string(jsonString))
	}

	f := args[0].(os.File)
	_, err = f.WriteString(msg.Raw)
	if err != nil {
		log.Println("Writing Error!!", err)
	}
}

func main() {
	// Request NetlinkSocket
	s, err := netlinkAudit.NewNetlinkConnection()
	if err != nil {
		log.Println(err)
		log.Fatalln("Error while availing socket, Exiting")
	}
	defer s.Close()

	// Enable Audit
	err = netlinkAudit.AuditSetEnabled(s)
	if err != nil {
		log.Fatal("Error while enabling Audit", err)
	}

	// Check if Audit is enabled
	status, err := netlinkAudit.AuditIsEnabled(s)

	if err == nil && status == 1 {
		log.Println("Enabled Audit")
	} else if err == nil && status == 0 {
		log.Fatalln("Audit Not Enabled")
	} else {
		log.Fatalln("Error while fetching status", err)
	}

	// Set the maximum number of messages
	// that the kernel will send per second
	// TODO - fetch these from config
	err = netlinkAudit.AuditSetRateLimit(s, 600)
	if err != nil {
		log.Fatalln("Error Setting Rate Limit", err)
	}

	// Set max limit audit message queue
	err = netlinkAudit.AuditSetBacklogLimit(s, 420)
	if err != nil {
		log.Fatalln("Error Setting Backlog Limit", err)
	}

	// Register current pid with audit
	err = netlinkAudit.AuditSetPid(s, uint32(syscall.Getpid()))
	if err == nil {
		log.Println("Set pid successful")
	}

	// Load all rules
	content, err := ioutil.ReadFile("audit.rules.json")
	if err != nil {
		log.Print("Error:", err)
		os.Exit(0)
	}

	// Set audit rules
	err = netlinkAudit.SetRules(s, content)
	// err = netlinkAudit.DeleteAllRules(s)
	if err != nil {
		log.Fatalln("Setting Rules Unsuccessful, Exiting")
	}

	f, err := os.OpenFile("/tmp/log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0660)
	if err != nil {
		log.Fatalln("Unable to open file")
	}
	defer f.Close()
	errchan := make(chan error)

	// Go rutine to monitor events and feet AuditEvent type events to the callback
	netlinkAudit.GetAuditEvents(s, EventCallback, errchan, *f)

	time.Sleep(3600 * time.Second)
}
