package main

import (
	"./libaudit-go"
	"log"
	"os"
	"os/signal"
	"io/ioutil"
	"syscall"
	"time"
)

var done chan bool
var debug bool

func main() {
	// Request NetlinkSocket
	s, err := netlinkAudit.NewNetlinkConnection()
	if err != nil {
		log.Println(err)
		log.Fatalln("Error while availing socket! Exiting!")
	}
	defer s.Close()
	debug = false

	// Enable Audit
	err = netlinkAudit.AuditSetEnabled(s)
	if err != nil {
		log.Fatal("Error while enabling Audit !", err)
	}

	// Check if Audit is enabled
	status, err := netlinkAudit.AuditIsEnabled(s)

	if err == nil && status == 1 {
		log.Println("Enabled Audit!!")
	} else  if err == nil && status == 0 {
		log.Fatalln("Audit Not Enabled!")
	} else {
		log.Fatalln("Error while fetching status!",)
	}

	// Set the maximum number of messages
	// that the kernel will send per second
	err = netlinkAudit.AuditSetRateLimit(s, 600)
	if err != nil {
		log.Fatalln("Error Setting Rate Limit!!", err)
	}

	// Set max limit audit message queue
	err = netlinkAudit.AuditSetBacklogLimit(s, 420)
	if err != nil {
		log.Fatalln("Error Setting Backlog Limit!!", err)
	}

	// Register current pid with audit
    err = netlinkAudit.AuditSetPid(s, uint32(syscall.Getpid()))
	if err == nil {
		log.Println("Set pid successful!!")
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
		log.Fatalln("Setting Rules Unsuccessful! Exiting")
	}
	

	done := make(chan bool, 1)
	msg := make(chan string)
	errchan := make(chan error)
	exit :=  make(chan os.Signal, 1)

	// Go rutine to monitor events and send them to channels
	go netlinkAudit.Getreply(s, done, msg, errchan)

	// Go rutine to extract events from channels
	go func() {
		f, err := os.OpenFile("/tmp/log", os.O_CREATE|os.O_RDWR|os.O_APPEND, 0660)	
		if err != nil {
			log.Fatalln("Error Creating File!!")
		}
		defer f.Close()

		for {
			select {
				case ev := <-msg:
					log.Println(ev + "\n")
					_, err := f.WriteString(ev + "\n")
					if err != nil {
						log.Println("Writing Error!!")
					}
				case ev := <-errchan:
					log.Println(ev)
			}
		}
	}()

	// Notify when control-c is pressed
	signal.Notify(exit, os.Interrupt)
	signal.Notify(exit, syscall.SIGTERM)
	go func() {
        <-exit
        done <- true
		close(done)
        os.Exit(1)
    }()


    for {
    	time.Sleep(time.Second * 5)	
    }
	
	//Important point is that NLMSG_ERROR is also an acknowledgement from Kernel.
	//If the first 4 bytes of Data part are zero then it means the message is acknowledged
}
