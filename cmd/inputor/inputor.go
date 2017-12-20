package main

import (
	"github.com/devplayg/siem"
	"github.com/devplayg/siem/inputor"
	//"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"os"
)

const (
	AppName    = "Data Inputor"
	AppVersion = "2.0.1"
)

func main() {
	var (
		version   = siem.CmdFlags.Bool("v", false, "Version")
		debug     = siem.CmdFlags.Bool("debug", false, "Debug")
		cpu       = siem.CmdFlags.Int("cpu", 2, "CPU Count")
		setConfig = siem.CmdFlags.Bool("config", false, "Edit configurations")
		interval  = siem.CmdFlags.Int64("i", 5000, "Interval(ms)")
	)
	siem.CmdFlags.Usage = siem.PrintHelp
	siem.CmdFlags.Parse(os.Args[1:])

	// Display version
	if *version {
		siem.DisplayVersion(AppName, AppVersion)
		return
	}

	// Start engine
	engine := siem.NewEngine(*debug, *cpu, *interval)
	if *setConfig {
		engine.SetConfig("storage.watchDir")
		return
	}
	if err := engine.Start(); err != nil {
		log.Error(err)
		return
	}
	log.Debug(engine.Config)

	// Start application
	app := inputor.NewInputor(engine)
	app.Start()
	log.Info("Started")

	// Start http server
	//r := mux.NewRouter()
	////	r.HandleFunc("/rank/{groupid:-?[0-9]+}/{category}/{top:[0-9]+}", rankHandler)
	//r.PathPrefix("/debug").Handler(http.DefaultServeMux)
	//log.Fatal(http.ListenAndServe(DefaultServerAddr, r))

	// Wait for signal
	siem.WaitForSignals()
}
