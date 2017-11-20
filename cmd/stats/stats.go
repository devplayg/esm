package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/devplayg/esm"
	"github.com/devplayg/esm/stats"
	log "github.com/sirupsen/logrus"
)

const (
	ProductName    = "SNIPER APTX-T Statistics Manager"
	ProductKeyword = "esmstats"
	ProductVersion = "2.0"
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
		interval = fs.Int64("i", 3000, "Interval(ms)")
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

	if err := esm.InitDatabase("192.168.239.128", 3306, "root", "sniper123!@#", "aptxm"); err != nil {
		log.Fatal(err)
	}

	// Start engine
	statist := stats.NewStatist(*interval)
	statist.Start(errChan)

	esm.WaitForSignals()
}

func printHelp() {
	fmt.Println("inputor")
	fs.PrintDefaults()
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
