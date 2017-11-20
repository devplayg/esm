package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	log "github.com/sirupsen/logrus"

	"github.com/devplayg/esm"
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
		version = fs.Bool("v", false, "Version")
		debug   = fs.Bool("d", false, "Debug")
		cpu     = fs.Int("cpu", 1, "CPU Count")
	)
	fs.Usage = printHelp
	fs.Parse(os.Args[1:])

	//
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
	//		esm.LogDrain
	go esm.LogDrain(errChan)

	// Start engine
	//	engine, err := inputor.NewEngine(*dbUser, *dbPass, *homeDir, *interval)
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//	engine.Start(errChan)
	//	log.Info("Started")

	//	waitForSignals()
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
