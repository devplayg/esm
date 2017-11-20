package esm

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	log "github.com/sirupsen/logrus"
)

func InitLogger(level log.Level, keyword string) {
	// Set log format
	log.SetFormatter(&log.TextFormatter{
		ForceColors:   true,
		DisableColors: true,
	})

	// Set log level
	log.SetLevel(level)
	if log.GetLevel() != log.InfoLevel {
		log.Infof("logginglevel=%s", log.GetLevel())
	}

	// Set log file
	logFile := filepath.Join("/var/log", keyword+".log")
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err == nil {
		log.SetOutput(file)
	} else {
		log.Error("Failed to log to file, using default stderr")
		log.SetOutput(os.Stdout)
	}
}

func LogDrain(errChan <-chan error) {
	for {
		select {
		case err := <-errChan:
			if err != nil {
				log.Error(err.Error())
			}
		}
	}
}

func WaitForSignals() {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	select {
	case <-signalCh:
		log.Println("Signal received, shutting down...")
	}
}
