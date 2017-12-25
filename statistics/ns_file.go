package statistics

import (
	"github.com/devplayg/siem"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
	"sync"
	"time"

	"encoding/json"
	"github.com/devplayg/golibs/orm"
	"sort"
	"strconv"
)

type nsFileStats struct {
	Stats
	dataMap      DataMap
	_rank        DataRank
	rank         DataRank
	memberAssets map[int][]int
}

func NewNsFileStats(engine *siem.Engine, router *mux.Router) *nsFileStats {
	return &nsFileStats{
		Stats: Stats{
			Name:   "ns_file",
			Engine: engine,
			Router: router,
		},
	}
}
func (s *nsFileStats) Start() error {
	go func() {
		for {
			rwMutex := new(sync.RWMutex)

			// Update assets
			assets, err := siem.GetMemberAssets()
			if err != nil {
				log.Error(err)
			} else {
				rwMutex.Lock()
				s.memberAssets = assets
				rwMutex.Unlock()
			}

			s.dataMap = make(DataMap)
			s._rank = make(DataRank)
			err = s.calculate()
			if err != nil {
				log.Error(err)
			} else {
				rwMutex.Lock()
				s.rank = s._rank
				rwMutex.Unlock()
			}

			// Sleep
			log.Debugf("Sleep %3.1fs", (time.Duration(s.Stats.Engine.Interval) * time.Millisecond).Seconds())
			time.Sleep(time.Duration(s.Stats.Engine.Interval) * time.Millisecond)
		}
	}()

	s.addRoute()
	return nil
}

//
func (s *nsFileStats) calculate() error {
	t1 := time.Now()
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
	startDate := t1.Format("2006-01-02") + " 00:00:00"
	endDate := t1.Format("2006-01-02") + " 23:59:59"

	var rows []siem.DownloadLog
	o := orm.NewOrm()
	_, err := o.Raw(query, startDate, endDate).QueryRows(&rows)
	if err != nil {
		return err
	}

	// Classify data
	t2 := time.Now()
	for _, r := range rows {
		s.addToStats(r, "srcip", r.SrcIp)
		s.addToStats(r, "dstip", r.DstIp)
		s.addToStats(r, "md5", r.Md5)
	}
	t3 := time.Now()

	// Determine rankings
	for id, m1 := range s.dataMap {
		for category, data := range m1 {
			s._rank[id][category] = determineRankings(data, 0)
		}
	}
	t4 := time.Now()
	log.Debugf("Query=%3.1f, Classify=%3.1f, Rankings=%3.1f", t2.Sub(t1).Seconds(), t3.Sub(t2).Seconds(), t4.Sub(t3).Seconds())

	return nil
}

func (s *nsFileStats) addToStats(r siem.DownloadLog, category string, val interface{}) error {

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

	return nil
}

func determineRankings(m map[interface{}]int64, top int) siem.ItemList {
	list := make(siem.ItemList, len(m))
	i := 0
	for k, v := range m {
		list[i] = siem.Item{k, v}
		i++
	}
	sort.Sort(sort.Reverse(list))
	if top > 0 && len(list) > top {
		return list[0:top]
	} else {
		return list
	}
}

func (s *nsFileStats) getRank(groupId int, category string, top int) siem.ItemList {
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

func (s *nsFileStats) addRoute() {
	s.Router.HandleFunc("/rank/{groupId:-?[0-9]+}/{category}/{top:[0-9]+}", s.rankHandler)
}

func (s *nsFileStats) GetName() string {
	return s.Name
}
