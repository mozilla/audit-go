package main

import (
	"./libaudit-go"
	"log"
	"os"
	//"io/ioutil"
	"syscall"
	"encoding/json"
	"os/exec"
	"strconv"
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

	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	out, err := exec.Command(dir+"/tools/rules2json.py", dir+"/"+os.Args[1]).Output()
	if err != nil {
		log.Fatal(err)
	}

	var m interface{}
	err = json.Unmarshal(out, &m)
	rules:= m.(map[string]interface{})

	// Enable Audit
	err = netlinkAudit.AuditSetEnabled(s, 1)
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

	//Delete all rules
	if _, ok := rules["delete"]; ok {
		log.Println("Deleting all rules")
		err = netlinkAudit.DeleteAllRules(s)
		if err != nil {
			log.Fatalln("Deleting Rules Unsuccessful, Exiting", err)
		}
	}

	// Set the maximum number of messages
	// that the kernel will send per second
	var i string
	if _, ok := rules["rate"]; ok {
		i = rules["rate"].(string)
	} else {
		i = "600"
	}
	r,err := strconv.Atoi(i)
	if err != nil {
		log.Fatalln("Error converting rate limit to integer", err)
	}

	err = netlinkAudit.AuditSetRateLimit(s, r)
	if err != nil {
		log.Fatalln("Error Setting Rate Limit", err)
	}

	// Set max limit audit message queue
	if _, ok := rules["buffer"]; ok {
		i = rules["rate"].(string)
	} else {
		i = "420"
	}
	b, _ := strconv.Atoi(i)
	err = netlinkAudit.AuditSetBacklogLimit(s, b)
	if err != nil {
		log.Fatalln("Error Setting Backlog Limit", err)
	}


	// Register current pid with audit
	err = netlinkAudit.AuditSetPid(s, uint32(syscall.Getpid()))
	if err == nil {
		log.Println("Set pid successful")
	}

	// Set audit rules
	err = netlinkAudit.SetRules(s, out)
	if err != nil {
		log.Fatalln("Setting Rule Unsuccessful: ", err)
	}

	
	f, err := os.OpenFile("/tmp/log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0660)
	if err != nil {
		log.Fatalln("Unable to open file")
	}
	defer f.Close()
	errchan := make(chan error)

	// Go rutine to monitor events and feet AuditEvent type events to the callback
	netlinkAudit.GetAuditEvents(s, EventCallback, errchan, *f)

	select {}
}
