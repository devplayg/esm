package main

import (
	//	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	//	"strconv"

	"github.com/devplayg/esm"
	"github.com/devplayg/esm/inputor"
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
	)
	fs.Usage = printHelp
	fs.Parse(os.Args[1:])

	// Version
	if *version {
		fmt.Printf("%s %s\n", ProductName, ProductVersion)
		return
	}

	// Debug
	if *debug {
		esm.InitLogger(log.DebugLevel, ProductKeyword)
	} else {
		esm.InitLogger(log.InfoLevel, ProductKeyword)
	}

	// CPU
	runtime.GOMAXPROCS(*cpu)

	// Start
	errChan := make(chan error)
	go esm.LogDrain(errChan)

	if err := esm.InitDatabase("127.0.0.1", 3306, "root", "sniper123!@#", "aptxm"); err != nil {
		log.Fatal(err)
	}

	// Start engine
	inputor := inputor.NewInputor(*interval, *watchDir)
	inputor.Start(errChan)

	// Start http server
	r := mux.NewRouter()
	//	r.HandleFunc("/rank/{groupid:-?[0-9]+}/{category}/{top:[0-9]+}", rankHandler)
	r.PathPrefix("/debug").Handler(http.DefaultServeMux)

	log.Fatal(http.ListenAndServe(DefaultServerAddr, r))

	// Wait
	esm.WaitForSignals()
}

func printHelp() {
	fmt.Println(ProductKeyword)
	fs.PrintDefaults()
}
