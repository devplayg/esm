package main

import (
	"flag"
	"fmt"
	"github.com/devplayg/siem"
	"github.com/devplayg/siem/inputor"
	//"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"strings"
)

const (
	ProductName    = "SNIPER APTX-T 5.0 Data Inputor"
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
		cpu       = fs.Int("cpu", 2, "CPU Count")
		setConfig = fs.Bool("config", false, "Edit configurations")
		interval  = fs.Int64("i", 5000, "Interval(ms)")
	)
	fs.Usage = printHelp
	fs.Parse(os.Args[1:])

	// Version
	if *version {
		fmt.Printf("%s, %s\n", ProductName, ProductVersion)
		return
	}

	engine := siem.NewEngine(*debug, *cpu, *interval)
	if *setConfig {
		err := engine.SetConfig("storage.watchDir")
		if err != nil {
			log.Error(err)
		} else {
			log.Info("Done")
		}
		return
	}
	if err := engine.Start(); err != nil {
		log.Error(err)
		return
	}

	log.Debug(engine.Config)
	app := inputor.NewInputor(engine)
	app.Start()

	// Start http server
	//r := mux.NewRouter()
	////	r.HandleFunc("/rank/{groupid:-?[0-9]+}/{category}/{top:[0-9]+}", rankHandler)
	//r.PathPrefix("/debug").Handler(http.DefaultServeMux)
	//log.Fatal(http.ListenAndServe(DefaultServerAddr, r))

	// Wait
	siem.WaitForSignals()
}

func printHelp() {
	fmt.Println(strings.TrimSuffix(filepath.Base(os.Args[0]), filepath.Ext(os.Args[0])))
	fs.PrintDefaults()
}
