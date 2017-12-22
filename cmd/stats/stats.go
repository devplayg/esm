package main

import (
	"github.com/devplayg/siem"
	"github.com/devplayg/siem/stats"
	log "github.com/sirupsen/logrus"
	_ "net/http/pprof"
	"os"
)

const (
	AppName           = "stats"
	AppVersion        = "2.0.2"
	DefaultServerAddr = "127.0.0.1:8080"
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
	log.Debug(engine.Config)

	// Start application
	app := stats.NewStatsCal("nsFiletrans", engine)
	app.Start()


	/*

	nsFileTransStats := stats.NewNsFileTransStatsCal(engine)
	nsFileTransStats.Start()


	 */


	// Wait for signal
	siem.WaitForSignals()
}
