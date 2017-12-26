package statistics

import (
	"encoding/json"
	//"fmt"
	"github.com/astaxie/beego/orm"
	"github.com/devplayg/siem"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strconv"
	"sync"
	"time"
	//"io/ioutil"
	//"os"
	"io/ioutil"
	"os"
	"fmt"
)

type nsFileStats struct {
	Stats
	dataMap      DataMap
	_rank        DataRank
	rank         DataRank
	memberAssets map[int][]int
	mutex        *sync.RWMutex
	o            orm.Ormer
	t            time.Time
}

func NewNsFileStats(engine *siem.Engine, router *mux.Router) *nsFileStats {
	return &nsFileStats{
		Stats: Stats{
			name:   "ns_file",
			Engine: engine,
			Router: router,
		},
	}
}

func (s *nsFileStats) Start() error {
	s.mutex = new(sync.RWMutex)
	s.o = orm.NewOrm()
	go func() {
		for {

			// Update assets
			assets, err := siem.GetMemberAssets()
			if err != nil {
				log.Error(err)
			} else {
				s.mutex.Lock()
				s.memberAssets = assets
				s.mutex.Unlock()
			}

			s.t = time.Now()
			//log.Debugf("##1 %s", s.t.Format("2006-01-02T15:04:05"))
			s.dataMap = make(DataMap)
			s._rank = make(DataRank)
			err = s.calculate()
			if err != nil {
				log.Error(err)
			} else {
				s.mutex.Lock()
				s.rank = s._rank
				s.mutex.Unlock()
			}

			// Sleep
			log.Debugf("Sleep %3.1fs", (time.Duration(s.Stats.Engine.Interval) * time.Millisecond).Seconds())
			time.Sleep(time.Duration(s.Stats.Engine.Interval) * time.Millisecond)
		}
	}()

	s.addRoute()
	return nil
}

func (s *nsFileStats) calculate() error {
	query := `
		select 	t.rdate,
				(sensor_code + 100000) sensor_code,
				trans_type,
				ippool_src_gcode,
				ippool_src_ocode,
				session_id,
				src_ip,
				src_port,
				src_country,
				dst_ip,
				dst_port,
				dst_country,
				domain,
				url,
				t.filesize,
				filename,
				t.md5,
				mail_sender,
				mail_recipient,
				score
		from log_event_filetrans t left outer join pol_file_md5 t1 on t1.md5 = t.md5
		where t.rdate >= ? and t.rdate <= ?
	`
	startDate := s.t.Format("2006-01-02") + " 00:00:00"
	endDate := s.t.Format("2006-01-02") + " 23:59:59"

	var rows []siem.DownloadLog
	o := orm.NewOrm()
	_, err := o.Raw(query, startDate, endDate).QueryRows(&rows)
	if err != nil {
		return err
	}

	// Classify data
	t1 := time.Now()
	for _, r := range rows {
		s.addToStats(&r, "srcip", r.SrcIp, false)
		s.addToStats(&r, "dstip", r.DstIp, false)
		s.addToStats(&r, "md5", r.Md5, false)
	}
	t2 := time.Now()

	// Determine rankings
	for id, m := range s.dataMap {
		for category, data := range m {
			s._rank[id][category] = determineRankings(data, 5)
			//err := s.insert(category, id, s._rank[id][category])
			//if err != nil {
			//	return err
			//}
		}
	}
	t3 := time.Now()

	err = s.insert()
	if err != nil {
		return err
	}
	log.Infof("Query=%3.1f, RowCount=%d, Classify=%3.1f, Insert=%3.1f", t1.Sub(s.t).Seconds(), len(rows), t2.Sub(t1).Seconds(), t3.Sub(t2).Seconds())

	return nil
}

func (s *nsFileStats) insert() error {
	fm := make(map[string]*os.File)
	defer func() {
		for _, f := range fm {
			//log.Debug(f.Name())
			f.Close()
			os.Remove(f.Name())
		}
	}()
	for id, m := range s._rank {
		for category, list := range m {
			if _, ok := fm[category]; !ok {
				tempFile, err := ioutil.TempFile("", category+"_")
				if err != nil {
					return err
				}
				fm[category] = tempFile
			}

			for i, item := range list {
				str := fmt.Sprintf("%s\t%d\t%v\t%d\t%d\n", s.t.Format("2006-01-02 15:04:05"), id, item.Key, item.Count, i+1)
				fm[category].WriteString(str)
			}
		}
	}

	for category, f := range fm {
		f.Close()
		query := fmt.Sprintf("LOAD DATA LOCAL INFILE %q INTO TABLE stat_%s", f.Name(), category)
		res, err := s.o.Raw(query).Exec()
		if err == nil {
			num, _ := res.RowsAffected()
			//log.Debugf("query=%s", query)
			log.Debugf("affectedRows=%d, category=%s", num, category)
		} else {
			return err
		}
	}

	// Bulk insert
	//tempFile, err := ioutil.TempFile("", "")
	//if err != nil {
	//	return err
	//}
	//defer func() {
	//	tempFile.Close()
	//	os.Remove(tempFile.Name())
	//}()
	//
	//for i, item := range list {
	//	str := fmt.Sprintf("%s\t%d\t%v\t%d\t%d\n", s.t.Format("2006-01-02 15:04:05"), id, item.Key, item.Count, i+1)
	//	tempFile.WriteString(str)
	//}
	//tempFile.Close()
	//res, err := s.o.Raw(fmt.Sprintf("LOAD DATA LOCAL INFILE %q INTO TABLE stat_%s", tempFile.Name(), category)).Exec()
	//if err == nil {
	//	num, _ := res.RowsAffected()
	//	log.Debugf("Category: %s, Affected rows: %d ", category, num)
	//} else {
	//	return err
	//}
	//return nil

	//// Insert (Prepared statement)
	//err := o.Begin()
	//key := strings.TrimSuffix(category, "_mal")
	//query := fmt.Sprintf("INSERT INTO stat_%s(rdate, folder_id, %s, count, rank) values(?, ?, ?, ?, ?)", category, key)
	//p, err := s.o.Raw(query).Prepare()
	//if err != nil {
	//	return err
	//}
	//for i, item := range s._rank[id][category] {
	//	//log.Infof("       %d - %s - [%d] %v - %d", id, category, i+1, item.Key, item.Count)
	//	_, err = p.Exec(s.t.Format("2006-01-02 15:04:05"), id, item.Key, item.Count, i+1)
	//	if err != nil {
	//		return err
	//	}
	//
	//}
	//p.Close()
	//o.Commit()

	return nil
}

func (s *nsFileStats) addToStats(r *siem.DownloadLog, category string, val interface{}, isMalicious bool) error {

	// By sensor
	if r.SensorCode > 0 {
		if _, ok := s.dataMap[r.SensorCode]; !ok {
			s.dataMap[r.SensorCode] = make(map[string]map[interface{}]int64)
			s._rank[r.SensorCode] = make(map[string]siem.ItemList)
		}
		if _, ok := s.dataMap[r.SensorCode][category]; !ok {
			s.dataMap[r.SensorCode][category] = make(map[interface{}]int64)
			s._rank[r.SensorCode][category] = nil
		}
		s.dataMap[r.SensorCode][category][val] += 1
	}

	// By group
	if r.IppoolSrcGcode > 0 {
		if _, ok := s.dataMap[r.IppoolSrcGcode]; !ok {
			s.dataMap[r.IppoolSrcGcode] = make(map[string]map[interface{}]int64)
			s._rank[r.IppoolSrcGcode] = make(map[string]siem.ItemList)
		}
		if _, ok := s.dataMap[r.IppoolSrcGcode][category]; !ok {
			s.dataMap[r.IppoolSrcGcode][category] = make(map[interface{}]int64)
			s._rank[r.IppoolSrcGcode][category] = nil
		}
		s.dataMap[r.IppoolSrcGcode][category][val] += 1
	}

	// To all
	if _, ok := s.dataMap[ALL]; !ok {
		s.dataMap[ALL] = make(map[string]map[interface{}]int64)
		s._rank[ALL] = make(map[string]siem.ItemList)
	}
	if _, ok := s.dataMap[ALL][category]; !ok {
		s.dataMap[ALL][category] = make(map[interface{}]int64)
		s._rank[ALL][category] = nil
	}
	s.dataMap[ALL][category][val] += 1

	// By member
	if arr, ok := s.memberAssets[r.IppoolSrcGcode]; ok {
		for _, memberId := range arr {
			id := memberId * -1

			if _, ok := s.dataMap[id]; !ok {
				s.dataMap[id] = make(map[string]map[interface{}]int64)
				s._rank[id] = make(map[string]siem.ItemList)
			}
			if _, ok := s.dataMap[id][category]; !ok {
				s.dataMap[id][category] = make(map[interface{}]int64)
				s._rank[id][category] = nil
			}
			s.dataMap[id][category][val] += 1
		}
	}

	// Malicious file
	if r.Score == 100 && !isMalicious {
		s.addToStats(r, category+"_mal", val, true)
	}
	return nil
}

func (s *nsFileStats) getRank(groupId int, category string, top int) siem.ItemList {
	s.mutex.RLock()

	defer s.mutex.RUnlock()
	if _, ok := s.rank[groupId]; ok {
		if list, ok2 := s.rank[groupId][category]; ok2 {
			if top > 0 && len(list) > top {
				return list[:top]
			} else {
				return list
			}
		}
	}
	return nil
}

func (s *nsFileStats) rankHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	groupId, _ := strconv.Atoi(vars["groupId"])
	top, _ := strconv.Atoi(vars["top"])

	list := s.getRank(groupId, vars["category"], top)
	buf, _ := json.Marshal(list)
	w.Write(buf)
}

func (s *nsFileStats) rankAll(w http.ResponseWriter, r *http.Request) {
	s.mutex.RLock()
	buf, _ := json.Marshal(s.rank)
	s.mutex.RUnlock()
	w.Write(buf)
}

func (s *nsFileStats) addRoute() {
	s.Router.HandleFunc("/rank/{groupId:-?[0-9]+}/{category}/{top:[0-9]+}", s.rankHandler)
	s.Router.HandleFunc("/rank", s.rankAll)
}

func (s *nsFileStats) GetName() string {
	return s.name
}

//
//func (s *nsFileStats) insert() error {
//	log.Debug("##3")
//	for id, m1 := range s.rank {
//		//log.Debugf("    id - %d", id)
//		for category, list := range m1 {
//			//log.Debugf("    %d - %s", id, category)
//			query := fmt.Sprintf("INSERT INTO stat_%s(rdate, folder_id, %s, count, rank) values(?, ?, ?, ?, ?)", category, category)
//			p, err := s.o.Raw(query).Prepare()
//			if err != nil {
//				log.Error(err)
//				return err
//			}
//			//
//			for i, item := range list {
//				log.Printf("       %d - %s - [%d] %v - %d", id, category, i+1, item.Key, item.Count)
//				//		p.Exec(s.t.Format("2006-01-02 15:04:05"), id, item.Key, item.Count, i+1)
//			}
//			p.Close()
//		}
//	}
//
//	return nil
//}
