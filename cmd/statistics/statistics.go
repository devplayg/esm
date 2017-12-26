package main

import (
	"github.com/devplayg/siem"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
	_ "net/http/pprof"
	"os"
	"github.com/devplayg/siem/statistics"
)

const (
	AppName    = "statistics"
	AppVersion = "2.0.3"
)

func main() {
	var (
		version   = siem.CmdFlags.Bool("v", false, "Version")
		debug     = siem.CmdFlags.Bool("debug", false, "Debug")
		cpu       = siem.CmdFlags.Int("cpu", 2, "CPU Count")
		setConfig = siem.CmdFlags.Bool("config", false, "Edit configurations")
		interval  = siem.CmdFlags.Int64("i", 15000, "Interval(ms)")
	)
	siem.CmdFlags.Usage = siem.PrintHelp
	siem.CmdFlags.Parse(os.Args[1:])

	// Display version
	if *version {
		siem.DisplayVersion(AppName, AppVersion)
		return
	}

	// Set configurations
	engine := siem.NewEngine(AppName, *debug, *cpu, *interval)
	if *setConfig {
		engine.SetConfig("server.addr")
		return
	}

	// Start engine
	if err := engine.Start(); err != nil {
		log.Error(err)
		return
	}
	log.Debug("engine started")

	// Start URL router and application
	router := mux.NewRouter()
	router.PathPrefix("/debug").Handler(http.DefaultServeMux)
	if err := startCalculatingStats(statistics.NewNsFileStats(engine, router)); err != nil {
		log.Error(err)
		return
	}
	go http.ListenAndServe(engine.Config["server.addr"], router)
	log.Debugf("HTTP server started. Listen: %s", engine.Config["server.addr"])

	// Wait for signal
	log.Debug("Waiting for signal..")
	siem.WaitForSignals()
}

func startCalculatingStats(s statistics.StatsCalculator) error {
	if err := s.Start(); err != nil {
		return err
	}
	log.Infof("Statistics(%s) started", s.GetName())
	return nil
}
