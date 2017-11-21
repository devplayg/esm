package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strconv"

	"github.com/devplayg/esm"
	"github.com/devplayg/esm/stats"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

const (
	ProductName       = "SNIPER APTX-T Statistics Manager"
	ProductKeyword    = "esmstats"
	ProductVersion    = "2.0"
	DefaultServerAddr = ":8080"
)

var (
	fs *flag.FlagSet
)

func main() {

	// Flags
	fs = flag.NewFlagSet("", flag.ExitOnError)
	var (
		version  = fs.Bool("v", false, "Version")
		debug    = fs.Bool("d", false, "Debug")
		cpu      = fs.Int("cpu", 1, "CPU Count")
		interval = fs.Int64("i", 10000, "Interval(ms)")
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
	statist := stats.NewStatist(*interval)
	statist.Start(errChan)

	// Start http server
	r := mux.NewRouter()
	r.HandleFunc("/rank/{groupid:-?[0-9]+}/{category}/{top:[0-9]+}", rankHandler)
	r.PathPrefix("/debug").Handler(http.DefaultServeMux)

	log.Fatal(http.ListenAndServe(DefaultServerAddr, r))

	// Wait
	esm.WaitForSignals()
}

func printHelp() {
	fmt.Println("inputor")
	fs.PrintDefaults()
}

func rankHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	groupId, _ := strconv.Atoi(vars["groupid"])
	top, _ := strconv.Atoi(vars["top"])

	list := stats.GetRank(groupId, vars["category"], top)
	buf, _ := json.Marshal(list)
	w.Write(buf)
}

//SpecialBuild
//ProductVersion
//ProductPrivatePart
//ProductName
//ProductMinorPart
//ProductMajorPart
//ProductBuildPart
//PrivateBuild
//OriginalFilename
//LegalTrademarks
//LegalCopyright
//IsSpecialBuild
//IsPreRelease
//IsPrivateBuild
//IsPatched
//IsDebug
//InternalName
//FileVersion
//FilePrivatePart
//FileName
//FileMinorPart
//FileMajorPart
//FileDescription
//FileBuildPart
//CompanyName
//Comments
//FileVersionInfo Class
