package esm

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"fmt"

	"github.com/devplayg/golibs/orm"

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

//func rankByCount(m map[interface{}]uint32, top uint8) esm.ItemList {
//	list := make(esm.ItemList, len(m))
//	i := 0
//	for k, v := range m {
//		list[i] = esm.Item{k, v}
//		i++
//	}
//	sort.Sort(sort.Reverse(list))
//	if top > 0 {
//		return list[0:top]
//	} else {
//		return list
//	}
//}
