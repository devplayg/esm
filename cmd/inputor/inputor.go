package main

import (
	"flag"
	"fmt"
	"os"
	//"runtime"

	"github.com/devplayg/siem"
	//"github.com/devplayg/siem/inputor"
	//"github.com/gorilla/mux"
	"github.com/devplayg/siem/inputor"
	log "github.com/sirupsen/logrus"
	"github.com/blevesearch/bleve/analysis/lang/in"
	"github.com/ekanite/ekanite/input"
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
		cpu       = fs.Int("cpu", 2, "CPU Count")
		setConfig = fs.Bool("config", false, "Set configuration")
		interval  = fs.Int64("i", 2000, "Interval(ms)")
	)
	fs.Usage = printHelp
	fs.Parse(os.Args[1:])

	// Version
	if *version {
		fmt.Printf("%s %s\n", ProductName, ProductVersion)
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
	}
	if err := engine.Start(); err != nil {
		log.Error(err)
	}

	siemInputor := inputor.NewInputor(engine)
	siemInputor.Start()
	//log.Info("Started")

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
