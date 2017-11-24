package inputor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/devplayg/esm"
	"github.com/devplayg/golibs/orm"
	_ "github.com/go-sql-driver/mysql"
	log "github.com/sirupsen/logrus"
)

type Inputor struct {
	dir      string
	interval int64
}

func NewInputor(interval int64, dir string) *Inputor {
	return &Inputor{
		dir:      dir,
		interval: interval,
	}
}

func (e *Inputor) Start(errChan chan<- error) error {

	go func() {
		for {
			o := orm.NewOrm()

			// Read sensors
			sensors, err := esm.GetSensors()
			if err != nil {
				errChan <- err
				continue
			}

			// Read files home directory and insert into tables
			for _, s := range sensors {
				dir := filepath.Join(e.dir, s.Ip)
				log.Debugf("Reading directory: %s", dir)

				// If directory exists
				if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
					err := filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {
						if !f.IsDir() {
							var e1 error

							if strings.HasSuffix(path, ".1") {
								e1 = e.insertEvent1(o, path)

							} else if strings.HasSuffix(path, ".2") {
								e1 = e.insertEvent2(o, path)

							} else if strings.HasSuffix(path, ".3") {
								e1 = e.insertEvent3(o, path)
							} else {
								os.Remove(path)
							}
							if e1 != nil {
								errChan <- e1
								log.Error(path)
								os.Rename(path, path+".err")
							} else {
								os.Remove(path)
							}
						}
						return nil
					})

					if err != nil {
						errChan <- err
						continue
					}
				}
			}

			// Sleep
			log.Debugf("Sleep %3.1fs", (time.Duration(e.interval) * time.Millisecond).Seconds())
			time.Sleep(time.Duration(e.interval) * time.Millisecond)
		}
	}()

	return nil
}

func (e *Inputor) insertEvent1(o orm.Ormer, path string) error {
	query := `
		LOAD DATA LOCAL INFILE '%s'
		INTO TABLE log_event_filetrans
		FIELDS TERMINATED BY '\t'
		LINES TERMINATED BY '\r\n' (
			@dummy,
			@dummy,
			rdate,
			gdate,
			sensor_code,
			ippool_src_gcode,
			ippool_src_ocode,
			ippool_dst_gcode,
			ippool_dst_ocode,
			session_id,
			category1,
			category2,
			src_ip,
			src_port,
			dst_ip,
			dst_port,
			domain,
			url,
			trans_type,
			filename,
			filesize,
			md5,
			mail_sender,
			mail_recipient,
			mail_contents_type,
			mail_contents,
			download_result,
			src_country,
			dst_country,
			protocol
		)`
	query = fmt.Sprintf(query, filepath.ToSlash(path))
	rs, err := o.Raw(query).Exec()
	if err == nil {
		rowsAffected, _ := rs.RowsAffected()
		log.Debugf("Type: 1, Affected rows: %d", rowsAffected)
	}
	return err
}

func (e *Inputor) insertEvent2(o orm.Ormer, path string) error {
	query := `
		LOAD DATA LOCAL INFILE '%s'
		INTO TABLE log_event_common
		FIELDS TERMINATED BY '\t'
		LINES TERMINATED BY '\r\n' (
			@dummy,
			@dummy,
			rdate,
			gdate,
			sensor_code,
			ippool_src_gcode,
			ippool_src_ocode,
			ippool_dst_gcode,
			ippool_dst_ocode,
			session_id,
			category1,
			category2,
			src_ip,
			src_port,
			dst_ip,
			dst_port,
			domain,
			url,
			risk_level,
			result,
			src_country,
			dst_country,
			protocol
		)`
	query = fmt.Sprintf(query, filepath.ToSlash(path))
	rs, err := o.Raw(query).Exec()
	if err == nil {
		rowsAffected, _ := rs.RowsAffected()
		log.Debugf("Type: 2, Affected rows: %d", rowsAffected)
	}
	return err
}

func (e *Inputor) insertEvent3(o orm.Ormer, path string) error {
	query := `
		LOAD DATA LOCAL INFILE '%s'
		REPLACE INTO TABLE pol_file_md5
		FIELDS TERMINATED BY '\t'
		LINES TERMINATED BY '\r\n' (
			@dummy,
			@dummy,
			@dummy,
			md5,
			score,
			category,
			judge,
			filesize,
			filetype,
			private_type,
			private_string,
			detect_flag,
			local_vaccine,
			malware_name
		)`
	query = fmt.Sprintf(query, filepath.ToSlash(path))
	rs, err := o.Raw(query).Exec()
	if err == nil {
		rowsAffected, _ := rs.RowsAffected()
		log.Debugf("Type: 3, Affected rows: %d", rowsAffected)
	}
	return err
}
