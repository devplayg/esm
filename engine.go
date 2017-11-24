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

	"github.com/devplayg/golibs/crypto"
	"github.com/devplayg/golibs/orm"
	log "github.com/sirupsen/logrus"
)

var enckey = []byte("DEVPLAYG_ENCKEY_")

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
		//		log.Error("Failed to log to file, using default stderr")
		log.SetOutput(os.Stdout)
	}
}

func InitDatabase(host string, port uint16, user, password, database string) error {
	connStr := fmt.Sprintf(`%s:%s@tcp(%s:%d)/%s?allowAllFiles=true&charset=utf8&parseTime=true&loc=%s`, user, password, host, port, database, "Asia%2FSeoul")
	log.Debugf("Database connection string: %s", connStr)
	err := orm.RegisterDataBase("default", "mysql", connStr, 3, 3)
	return err
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

func SetDatabase() error {
	dbInfo := DbInfo{
		DriverName: "mysql",
	}

	fmt.Println("Setting database")
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Hostname : ")
	hostname, _ := reader.ReadString('\n')
	dbInfo.Host = strings.TrimSpace(hostname)
	fmt.Printf("Port     : ")
	port, _ := reader.ReadString('\n')
	dbInfo.Port = strings.TrimSpace(port)
	fmt.Printf("Username : ")
	username, _ := reader.ReadString('\n')
	dbInfo.Username = strings.TrimSpace(username)
	fmt.Printf("Password : ")
	password, _ := reader.ReadString('\n')
	dbInfo.Password = strings.TrimSpace(password)

	// Crypto

	ex, err := os.Executable()
	if err != nil {
		return err
	}
	filenameWithoutExt := strings.TrimSuffix(filepath.Base(ex), filepath.Ext(ex))
	fp := filepath.Join(filepath.Dir(ex), filenameWithoutExt+".enc")
	err = crypto.SaveObjectToEncryptedFile(fp, enckey, dbInfo)
	if err != nil {
		return err
	}
	return nil
}
