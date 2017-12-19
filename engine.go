package siem

import (
	"bufio"
	"encoding/gob"
	"fmt"
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
)

type Engine struct {
	debug       bool
	processName string
	logOutput   int // 0: STDOUT, 1: File
}

func NewEngine(debug bool) *Engine {
	return &Engine{
		processName: strings.TrimSuffix(filepath.Base(os.Args[0]), filepath.Ext(os.Args[0])),
		debug:       debug,
	}
}

func (e *Engine) Start(level log.Level) error {

}

func (e *Engine) InitLogger(level log.Level) error {
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
		fmt.Printf("Output: %s\n", file)
	} else {
		//		log.Error("Failed to log to file, using default stderr")
		e.logOutput = 0
		log.SetOutput(os.Stdout)
	}

	// Set log level
	log.SetLevel(level)
	if log.GetLevel() != log.InfoLevel {
		log.Infof("LoggingLevel=%s(%s)", log.GetLevel(), logFile)
	}

	return nil
}

var enckey = []byte("DEVPLAYG_ENCKEY_")

func InitLogger(level log.Level) {
	processName := strings.TrimSuffix(filepath.Base(os.Args[0]), filepath.Ext(os.Args[0]))
	// Set log format
	log.SetFormatter(&log.TextFormatter{
		ForceColors:   true,
		DisableColors: true,
	})

	// Set log file
	logFile := filepath.Join("/var/log", processName+".log")
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err == nil {
		log.SetOutput(file)
		fmt.Printf("Output: %s\n", file)
	} else {
		//		log.Error("Failed to log to file, using default stderr")
		log.SetOutput(os.Stdout)
	}

	// Set log level
	log.SetLevel(level)
	if log.GetLevel() != log.InfoLevel {
		fmt.Printf("logLevel=%s, logFile=%s\n", log.GetLevel(), logFile)
		log.Infof("LoggingLevel=%s(%s)", log.GetLevel(), logFile)
	}
}

func InitDatabase(keyword string) error {
	ex, err := os.Executable()
	if err != nil {
		return err
	}
	configPath := filepath.Join(filepath.Dir(ex), keyword+".enc")
	config, err := GetConfig(configPath)
	if err != nil {
		return err
	}
	connStr := fmt.Sprintf(`%s:%s@tcp(%s:%s)/%s?allowAllFiles=true&charset=utf8&parseTime=true&loc=%s`,
		config["db.username"],
		config["db.password"],
		config["db.hostname"],
		config["db.port"],
		config["db.database"],
		"Asia%2FSeoul")
	log.Debugf("Database connection string: %s", connStr)
	err = orm.RegisterDataBase("default", "mysql", connStr, 3, 3)
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

func SaveObject(path string, object interface{}) error {
	file, err := os.Create(path)
	if err == nil {
		encoder := gob.NewEncoder(file)
		encoder.Encode(object)
	}
	file.Close()
	return err
}

func LoadObject(path string, object interface{}) error {
	file, err := os.Open(path)
	if err == nil {
		decoder := gob.NewDecoder(file)
		err = decoder.Decode(object)
	}
	file.Close()
	return err
}

func GetConfig(configPath string) (map[string]string, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, errors.New("Configuration file not found ")
	} else {
		config := make(map[string]string)
		err := crypto.LoadEncryptedObjectFile(configPath, enckey, &config)
		return config, err
	}
}

func SetConfig(configPath string, extra string) error {
	config, err := GetConfig(configPath)
	if config == nil {
		config = make(map[string]string)
	}

	fmt.Println("Setting configuration")
	readInput("db.hostname", config)
	readInput("db.port", config)
	readInput("db.username", config)
	readInput("db.password", config)
	readInput("db.database", config)

	if len(extra) > 0 {
		arr := strings.Split(extra, ",")
		for _, k := range arr {
			readInput(k, config)
		}
	}
	//	fmt.Println(configPath)
	//	readInput("storage.home", config)

	err = crypto.SaveObjectToEncryptedFile(configPath, enckey, config)
	return err
}

func readInput(key string, config map[string]string) {
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
