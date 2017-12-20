package siem

import (
	"bufio"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	//"github.com/davecgh/go-spew/spew"

	"errors"

	"github.com/devplayg/golibs/crypto"
	"github.com/devplayg/golibs/orm"
	log "github.com/sirupsen/logrus"
	"runtime"
)

var enckey = []byte("DEVPLAYG_ENCKEY_")

type Engine struct {
	ConfigPath  string
	Config      map[string]string
	Interval    int64
	debug       bool
	cpuCount    int
	processName string
	logOutput   int // 0: STDOUT, 1: File
}

func NewEngine(debug bool, cpuCount int, interval int64) *Engine {
	e := Engine{
		processName: strings.TrimSuffix(filepath.Base(os.Args[0]), filepath.Ext(os.Args[0])),
		cpuCount:    cpuCount,
		debug:       debug,
		Interval:    interval,
	}
	e.ConfigPath = filepath.Join(filepath.Dir(os.Args[0]), e.processName+".enc")
	e.initLogger()
	return &e
}

func (e *Engine) Start() error {
	runtime.GOMAXPROCS(e.cpuCount)
	log.Debugf("GOMAXPROCS set to %d", runtime.GOMAXPROCS(0))
	config, err := e.getConfig()
	if err != nil {
		return err
	}
	e.Config = config

	err = e.initDatabase()
	if err != nil {
		return err
	}
	return nil
}

func (e *Engine) initLogger() error {

	// Set log format
	log.SetFormatter(&log.TextFormatter{
		ForceColors:   true,
		DisableColors: true,
	})

	// Set log file
	logFile := filepath.Join("/var/log", e.processName+".log")
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err == nil {
		log.SetOutput(file)
		e.logOutput = 1
		fmt.Printf("Output: %s\n", file.Name())
	} else {
		//		log.Error("Failed to log to file, using default stderr")
		e.logOutput = 0
		log.SetOutput(os.Stdout)
	}

	// Set log level
	if e.debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	if log.GetLevel() != log.InfoLevel {
		log.Infof("LoggingLevel=%s", log.GetLevel())
	}

	return nil
}

//func InitLogger(level log.Level) {
//	processName := strings.TrimSuffix(filepath.Base(os.Args[0]), filepath.Ext(os.Args[0]))
//	// Set log format
//	log.SetFormatter(&log.TextFormatter{
//		ForceColors:   true,
//		DisableColors: true,
//	})
//
//	// Set log file
//	logFile := filepath.Join("/var/log", processName+".log")
//	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
//	if err == nil {
//		log.SetOutput(file)
//		fmt.Printf("Output: %s\n", file)
//	} else {
//		//		log.Error("Failed to log to file, using default stderr")
//		log.SetOutput(os.Stdout)
//	}
//
//	// Set log level
//	log.SetLevel(level)
//	if log.GetLevel() != log.InfoLevel {
//		fmt.Printf("logLevel=%s, logFile=%s\n", log.GetLevel(), logFile)
//		log.Infof("LoggingLevel=%s(%s)", log.GetLevel(), logFile)
//	}
//}

func (e *Engine) initDatabase() error {
	connStr := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?allowAllFiles=true&charset=utf8&parseTime=true&loc=%s",
		e.Config["db.username"],
		e.Config["db.password"],
		e.Config["db.hostname"],
		e.Config["db.port"],
		e.Config["db.database"],
		"Asia%2FSeoul")
	log.Debugf("Database connection string: %s", connStr)
	err := orm.RegisterDataBase("default", "mysql", connStr, 3, 3)
	return err
}

//func CheckConfig(keyword string) error {
//	ex, err := os.Executable()
//	if err != nil {
//		return err
//	}
//	configPath := filepath.Join(filepath.Dir(ex), keyword+".enc")
//
//}
//
//func LogDrain(errChan <-chan error) {
//	for {
//		select {
//		case err := <-errChan:
//			if err != nil {
//				log.Error(err.Error())
//			}
//		}
//	}
//}

func WaitForSignals() {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	select {
	case <-signalCh:
		log.Println("Signal received, shutting down...")
	}
}

func (e *Engine) getConfig() (map[string]string, error) {
	if _, err := os.Stat(e.ConfigPath); os.IsNotExist(err) {
		return nil, errors.New("Configuration file not found: " + filepath.Base(e.ConfigPath))
	} else {
		config := make(map[string]string)
		err := crypto.LoadEncryptedObjectFile(e.ConfigPath, enckey, &config)
		return config, err
	}
}

func (e *Engine) SetConfig(extra string) error {
	config, err := e.getConfig()
	if config == nil {
		config = make(map[string]string)
	}

	fmt.Println("Setting configuration")
	e.readInput("db.hostname", config)
	e.readInput("db.port", config)
	e.readInput("db.username", config)
	e.readInput("db.password", config)
	e.readInput("db.database", config)

	if len(extra) > 0 {
		arr := strings.Split(extra, ",")
		for _, k := range arr {
			e.readInput(k, config)
		}
	}
	err = crypto.SaveObjectToEncryptedFile(e.ConfigPath, enckey, config)
	return err
}

func (e *Engine) readInput(key string, config map[string]string) {
	if val, ok := config[key]; ok && len(val) > 0 {
		fmt.Printf("%-15s = (%s) ", key, val)
	} else {
		fmt.Printf("%-15s = ", key)
	}

	reader := bufio.NewReader(os.Stdin)
	newVal, _ := reader.ReadString('\n')
	newVal = strings.TrimSpace(newVal)
	if len(newVal) > 0 {
		config[key] = newVal
	}
}
