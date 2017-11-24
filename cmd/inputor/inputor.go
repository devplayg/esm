package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"

	"github.com/devplayg/siem"
	"github.com/devplayg/siem/inputor"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

const (
	ProductName       = "SNIPER APTX-T Data Inputor"
	ProductKeyword    = "inputor"
	ProductVersion    = "2.0"
	DefaultServerAddr = "127.0.0.1:8080"
)

var (
	fs *flag.FlagSet
)

func main() {

	// Flags
	fs = flag.NewFlagSet("", flag.ExitOnError)
	var (
		version  = fs.Bool("v", false, "Version")
		debug    = fs.Bool("debug", false, "Debug")
		cpu      = fs.Int("cpu", 1, "CPU Count")
		interval = fs.Int64("i", 10000, "Interval(ms)")
		watchDir = fs.String("dir", "/home/sniper_bps/relation/", "Directory to watch")
		db       = fs.Bool("db", false, "Set database")
	)
	fs.Usage = printHelp
	fs.Parse(os.Args[1:])

	// Version
	if *version {
		fmt.Printf("%s %s\n", ProductName, ProductVersion)
		return
	}

	// DB setting
	if *db {
		err := siem.SetDatabase()
		if err != nil {
			log.Println(err.Error())
		}

		return
	}

	// Debug
	if *debug {
		siem.InitLogger(log.DebugLevel, ProductKeyword)
	} else {
		siem.InitLogger(log.InfoLevel, ProductKeyword)
	}

	// CPU
	runtime.GOMAXPROCS(*cpu)

	// Initialize database
	if err := siem.InitDatabase("127.0.0.1", 3306, "root", "sniper123!@#", "aptxm"); err != nil {
		log.Fatal(err)
	}

	// Logging
	errChan := make(chan error)
	go siem.LogDrain(errChan)

	// Start engine
	inputor := inputor.NewInputor(*interval, *watchDir)
	inputor.Start(errChan)

	// Start http server
	r := mux.NewRouter()
	//	r.HandleFunc("/rank/{groupid:-?[0-9]+}/{category}/{top:[0-9]+}", rankHandler)
	r.PathPrefix("/debug").Handler(http.DefaultServeMux)

	log.Fatal(http.ListenAndServe(DefaultServerAddr, r))

	// Wait
	siem.WaitForSignals()
}

func printHelp() {
	fmt.Println(ProductKeyword)
	fs.PrintDefaults()
}
