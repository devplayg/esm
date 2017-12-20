package main

import (
	"github.com/devplayg/siem"
	"github.com/devplayg/siem/stats"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
	_ "net/http/pprof"
	"os"
)

const (
	AppName    = "Statist"
	AppVersion = "2.0.1"
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
	engine := siem.NewEngine(*debug, *cpu, *interval)
	if *setConfig {
		engine.SetConfig("")
		return
	}
	// Start engine
	if err := engine.Start(); err != nil {
		log.Error(err)
		return
	}
	log.Debug(engine.Config)

	// Start application
	app := stats.NewStatist(engine)
	app.Start()
	log.Info("Started")

	// Start http server
	r := mux.NewRouter()
	//	//	r.HandleFunc("/rank/{groupid:-?[0-9]+}/{category}/{top:[0-9]+}", rankHandler)
	r.PathPrefix("/debug").Handler(http.DefaultServeMux)
	log.Fatal(http.ListenAndServe(DefaultServerAddr, r))

	// Wait for signal
	siem.WaitForSignals()
}

//package main
//
//import (
//	"flag"
//	"fmt"
//	"net/http"
//	_ "net/http/pprof"
//	"os"
//	"path/filepath"
//	"runtime"
//
//	"github.com/devplayg/siem"
//	"github.com/devplayg/siem/stats"
//	"github.com/gorilla/mux"
//	log "github.com/sirupsen/logrus"
//)
//
//const (
//	ProductName       = "SNIPER APTX-T Statistics Manager"
//	ProductKeyword    = "stats"
//	ProductVersion    = "2.0"
//	DefaultServerAddr = ":8080"
//)
//
//var (
//	fs *flag.FlagSet
//)
//
//func main() {
//	// Flags
//	fs = flag.NewFlagSet("", flag.ExitOnError)
//	var (
//		version   = fs.Bool("v", false, "Version")
//		debug     = fs.Bool("debug", false, "Debug")
//		cpu       = fs.Int("cpu", 1, "CPU Count")
//		setConfig = fs.Bool("config", false, "Set configuration")
//		interval  = fs.Int64("i", 10000, "Interval(ms)")
//	)
//	fs.Usage = printHelp
//	fs.Parse(os.Args[1:])
//
//	// Version
//	if *version {
//		fmt.Printf("%s %s\n", ProductName, ProductVersion)
//		return
//	}
//
//	// Debug
//	if *debug {
//		siem.InitLogger(log.DebugLevel, ProductKeyword)
//	} else {
//		siem.InitLogger(log.InfoLevel, ProductKeyword)
//	}
//
//	// Config
//	ex, err := os.Executable()
//	if err != nil {
//		log.Error(err)
//	}
//	configPath := filepath.Join(filepath.Dir(ex), ProductKeyword+".enc")
//
//	if *setConfig {
//		err := siem.SetConfig(configPath, "")
//		if err != nil {
//			log.Error(err)
//		}
//		return
//	}
//	config, _ := siem.GetConfig(configPath)
//	if config == nil {
//		log.Fatal("Configuration file not found.(Use '-config' option)")
//	}
//
//	// Initialize database
//	if err := siem.InitDatabase(ProductKeyword); err != nil {
//		log.Fatal(err)
//	}
//
//	// CPU
//	runtime.GOMAXPROCS(*cpu)
//	log.Debugf("GOMAXPROCS set to %d", runtime.GOMAXPROCS(0))
//
//	// Logging
//	errChan := make(chan error)
//	go siem.LogDrain(errChan)
//
//	// Start statistics
//	statist := stats.NewStatist(*interval)
//	statist.Start(errChan)
//	log.Info("Started")
//
//	// Start http server
//	r := mux.NewRouter()
//	//	r.HandleFunc("/rank/{groupid:-?[0-9]+}/{category}/{top:[0-9]+}", rankHandler)
//	r.PathPrefix("/debug").Handler(http.DefaultServeMux)
//	log.Fatal(http.ListenAndServe(DefaultServerAddr, r))
//
//	// Wait
//	siem.WaitForSignals()
//}
//
//func printHelp() {
//	fmt.Println(ProductKeyword)
//	fs.PrintDefaults()
//}
