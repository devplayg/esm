package stats

import (
	"sort"
	"sync"
	"time"

	"encoding/json"
	"github.com/devplayg/golibs/orm"
	"github.com/devplayg/siem"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strconv"
)

const (
	ALL = -1
)

var (
	ranker statsRank
)

// Code / Category / Key / Count
type statsMap map[int]map[string]map[interface{}]int64

// Code / Category / Key / Ranking
type statsRank map[int]map[string]siem.ItemList

type statsCal struct {
	engine         *siem.Engine
	statsMap       statsMap
	statsRank      statsRank
	membersByAsset map[int][]int
}

func NewStatsCal(engine *siem.Engine) *statsCal {
	return &statsCal{
		engine: engine,
	}
}

func (e *statsCal) Start() error {
	go func() {
		for {
			e.statsMap = make(statsMap)
			e.statsRank = make(statsRank)
			if err := e.updateMembersAssets(); err != nil {
				log.Error(err)
			}
			if err := e.generateStats(); err != nil {
				log.Error(err)
			}

			rwMutex := new(sync.RWMutex)
			rwMutex.Lock()
			ranker = e.statsRank
			rwMutex.Unlock()

			// Sleep
			log.Debugf("Sleep %3.1fs", (time.Duration(e.engine.Interval) * time.Millisecond).Seconds())
			time.Sleep(time.Duration(e.engine.Interval) * time.Millisecond)
		}
	}()

	go e.openHttpApi()
	return nil
}


func (e *statsCal) generateStats() error {
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
	sdate := t1.Format("2006-01-02") + " 00:00:00"
	edate := t1.Format("2006-01-02") + " 23:59:59"

	var rows []siem.DownloadLog
	o := orm.NewOrm()
	_, err := o.Raw(query, sdate, edate).QueryRows(&rows)
	if err != nil {
		return err
	}

	t2 := time.Now()
	for _, r := range rows {
		e.addToStats(r, "srcip", r.SrcIp)
		e.addToStats(r, "dstip", r.DstIp)
		e.addToStats(r, "md5", r.Md5)
	}
	t3 := time.Now()

	// Rank
	for id, m1 := range e.statsMap {
		for category, data := range m1 {
			e.statsRank[id][category] = rankByCount(data, 0)
		}
	}
	t4 := time.Now()
	log.Infof("Query=%3.1f, Statistics=%3.1f, Ranking=%3.1f", t2.Sub(t1).Seconds(), t3.Sub(t2).Seconds(), t4.Sub(t3).Seconds())

	return nil
}

func (e *statsCal) addToStats(r siem.DownloadLog, category string, val interface{}) error {

	// By sensor
	if r.SensorCode > 0 {
		if _, ok := e.statsMap[r.SensorCode]; !ok {
			e.statsMap[r.SensorCode] = make(map[string]map[interface{}]int64)
			e.statsRank[r.SensorCode] = make(map[string]siem.ItemList)
		}
		if _, ok := e.statsMap[r.SensorCode][category]; !ok {
			e.statsMap[r.SensorCode][category] = make(map[interface{}]int64)
			e.statsRank[r.SensorCode][category] = nil
		}
		e.statsMap[r.SensorCode][category][val] += 1
	}

	// By group
	if r.IppoolSrcGcode > 0 {
		if _, ok := e.statsMap[r.IppoolSrcGcode]; !ok {
			e.statsMap[r.IppoolSrcGcode] = make(map[string]map[interface{}]int64)
			e.statsRank[r.IppoolSrcGcode] = make(map[string]siem.ItemList)
		}
		if _, ok := e.statsMap[r.IppoolSrcGcode][category]; !ok {
			e.statsMap[r.IppoolSrcGcode][category] = make(map[interface{}]int64)
			e.statsRank[r.IppoolSrcGcode][category] = nil
		}
		e.statsMap[r.IppoolSrcGcode][category][val] += 1
	}

	// To all
	if _, ok := e.statsMap[ALL]; !ok {
		e.statsMap[ALL] = make(map[string]map[interface{}]int64)
		e.statsRank[ALL] = make(map[string]siem.ItemList)
	}
	if _, ok := e.statsMap[ALL][category]; !ok {
		e.statsMap[ALL][category] = make(map[interface{}]int64)
		e.statsRank[ALL][category] = nil
	}
	e.statsMap[ALL][category][val] += 1

	// By member
	if arr, ok := e.membersByAsset[r.IppoolSrcGcode]; ok {
		for _, memberId := range arr {
			id := memberId * -1

			if _, ok := e.statsMap[id]; !ok {
				e.statsMap[id] = make(map[string]map[interface{}]int64)
				e.statsRank[id] = make(map[string]siem.ItemList)
			}
			if _, ok := e.statsMap[id][category]; !ok {
				e.statsMap[id][category] = make(map[interface{}]int64)
				e.statsRank[id][category] = nil
			}
			e.statsMap[id][category][val] += 1
		}
	}

	return nil
}

func (e *statsCal) updateMembersAssets() error {
	query := "select asset_id, member_id from mbr_asset where asset_type = 2"
	m := make(map[int][]int)

	//	m := make(map[int]map[int]bool)
	o := orm.NewOrm()
	var rows []siem.MemberAsset
	_, err := o.Raw(query).QueryRows(&rows)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if _, ok := m[r.AssetId]; !ok {
			m[r.AssetId] = make([]int, 0)
		}
		m[r.AssetId] = append(m[r.AssetId], r.MemberId)
	}

	rwMutex := new(sync.RWMutex)
	rwMutex.Lock()
	e.membersByAsset = m
	rwMutex.Unlock()
	return nil

}

func rankByCount(m map[interface{}]int64, top int) siem.ItemList {
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

func getRank(groupId int, category string, top int) siem.ItemList {
	if _, ok := ranker[groupId]; ok {
		if list, ok2 := ranker[groupId][category]; ok2 {
			if top > 0 && len(list) > top {
				return list[:top]
			} else {
				return list
			}
		}
	}
	return nil
}

func rankHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	groupId, _ := strconv.Atoi(vars["groupId"])
	top, _ := strconv.Atoi(vars["top"])

	list := getRank(groupId, vars["category"], top)
	buf, _ := json.Marshal(list)
	w.Write(buf)
}

func (e *statsCal) openHttpApi() {
	// Start http server
	r := mux.NewRouter()
	r.HandleFunc("/rank/{groupId:-?[0-9]+}/{category}/{top:[0-9]+}", rankHandler)
	r.PathPrefix("/debug").Handler(http.DefaultServeMux)
	log.Fatal(http.ListenAndServe(e.engine.Config["server.addr"], r))
}
