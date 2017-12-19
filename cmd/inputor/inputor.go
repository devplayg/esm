package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/devplayg/siem"
	"github.com/devplayg/siem/inputor"
	//"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

const (
	ProductName    = "SNIPER APTX-T 5.0 Data Inputor"
	ProductKeyword = "inputor"
	ProductVersion = "2.0.0"
)

var (
	fs *flag.FlagSet
)

func main() {

	// Flags
	fs = flag.NewFlagSet("", flag.ExitOnError)
	var (
		version   = fs.Bool("v", false, "Version")
		debug     = fs.Bool("debug", false, "Debug")
		cpu       = fs.Int("cpu", 1, "CPU Count")
		setConfig = fs.Bool("config", false, "Set configuration")
		interval  = fs.Int64("i", 10000, "Interval(ms)")
	)
	fs.Usage = printHelp
	fs.Parse(os.Args[1:])

	// Version
	if *version {
		fmt.Printf("%s %s\n", ProductName, ProductVersion)
		return
	}

	// Start engine
	engine := siem.NewEngine(*debug)

	//	// Debug
	//	if *debug {
	//		siem.InitLogger(log.DebugLevel)
	//	} else {
	//		siem.InitLogger(log.InfoLevel)
	//	}

	// Config
	ex, err := os.Executable()
	if err != nil {
		log.Error(err)
	}
	configPath := filepath.Join(filepath.Dir(ex), ProductKeyword+".enc")

	if *setConfig {
		err := siem.SetConfig(configPath, "storage.watchDir")
		if err != nil {
			log.Error(err)
		}
		return
	}
	config, _ := siem.GetConfig(configPath)
	if config == nil {
		msg := "Configuration file not found.(Use '-config' option)"
		fmt.Println(msg)
		log.Fatal(msg)
		return
	}

	// Initialize database
	if err := siem.InitDatabase(ProductKeyword); err != nil {
		log.Fatal(err)
	}

	// CPU
	runtime.GOMAXPROCS(*cpu)
	log.Debugf("GOMAXPROCS set to %d", runtime.GOMAXPROCS(0))

	// Logging
	errChan := make(chan error)
	go siem.LogDrain(errChan)

	// Start inputor
	inputor := inputor.NewInputor(*interval, config["storage.watchDir"])
	inputor.Start(errChan)
	log.Info("Started")

	//// Start http server
	//r := mux.NewRouter()
	////	r.HandleFunc("/rank/{groupid:-?[0-9]+}/{category}/{top:[0-9]+}", rankHandler)
	//r.PathPrefix("/debug").Handler(http.DefaultServeMux)
	//log.Fatal(http.ListenAndServe(DefaultServerAddr, r))

	// Wait
	siem.WaitForSignals()
}

func printHelp() {
	fmt.Println(ProductKeyword)
	fs.PrintDefaults()
}
