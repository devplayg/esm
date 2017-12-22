package statistics

import "github.com/gorilla/mux"

type nsFile struct {
	name         string
	router       *mux.Router
	engine       *siem.Engine
	dataMap      DataMap
	_rank        DataRank
	rank         DataRank
	memberAssets map[int][]int
}

//import (
//	"github.com/devplayg/siem"
//	"sort"
//	"net/http"
//	"github.com/gorilla/mux"
//	"strconv"
//	"encoding/json"
//	log "github.com/sirupsen/logrus"
//	"sync"
//	"time"
//	"github.com/devplayg/golibs/orm"
//)

//func NewStatsCal(engine *siem.Engine, name string, router *mux.Router) *statsCal {
//	return &statsCal{
//		engine: engine,
//		name:   name,
//		router: router,
//	}
//}
//
//func (e *statsCal) Start() error {
//	go func() {
//		for {
//			e.dataMap = make(DataMap)
//			e._rank = make(DataRank)
//			if err := e.updateMemberAssets(); err != nil {
//				log.Error(err)
//			}
//			if err := e.calculateStats(); err != nil {
//				log.Error(err)
//			}
//
//			rwMutex := new(sync.RWMutex)
//			rwMutex.Lock()
//			e.rank = e._rank
//			rwMutex.Unlock()
//
//			// Sleep
//			log.Debugf("Sleep %3.1fs", (time.Duration(e.engine.Interval) * time.Millisecond).Seconds())
//			time.Sleep(time.Duration(e.engine.Interval) * time.Millisecond)
//		}
//	}()
//
//	//go e.openHttpApi()
//	e.addHttpApi()
//	log.Debugf("Stats(%s) stated", e.name)
//	return nil
//}
//
//func (e *statsCal) calculateStats() error {
//	t1 := time.Now()
//	query := `
//		select 	t.rdate,
//				(sensor_code + 100000) sensor_code,
//				trans_type,
//				ippool_src_gcode,
//				ippool_src_ocode,
//				session_id,
//				src_ip,
//				src_port,
//				src_country,
//				dst_ip,
//				dst_port,
//				dst_country,
//				domain,
//				url,
//				t.filesize,
//				filename,
//				t.md5,
//				mail_sender,
//				mail_recipient,
//				score
//		from log_event_filetrans t left outer join pol_file_md5 t1 on t1.md5 = t.md5
//		where t.rdate >= ? and t.rdate <= ?
//	`
//	sdate := t1.Format("2006-01-02") + " 00:00:00"
//	edate := t1.Format("2006-01-02") + " 23:59:59"
//
//	var rows []siem.DownloadLog
//	o := orm.NewOrm()
//	_, err := o.Raw(query, sdate, edate).QueryRows(&rows)
//	if err != nil {
//		return err
//	}
//
//	t2 := time.Now()
//	for _, r := range rows {
//		e.addToStats(r, "srcip", r.SrcIp)
//		e.addToStats(r, "dstip", r.DstIp)
//		e.addToStats(r, "md5", r.Md5)
//	}
//	t3 := time.Now()
//
//	// Rank
//	for id, m1 := range e.dataMap {
//		for category, data := range m1 {
//			e._rank[id][category] = determinRanking(data, 0)
//		}
//	}
//	t4 := time.Now()
//	log.Infof("Query=%3.1f, Statistics=%3.1f, Ranking=%3.1f", t2.Sub(t1).Seconds(), t3.Sub(t2).Seconds(), t4.Sub(t3).Seconds())
//
//	return nil
//}
//
//func (e *statsCal) addToStats(r siem.DownloadLog, category string, val interface{}) error {
//
//	// By sensor
//	if r.SensorCode > 0 {
//		if _, ok := e.dataMap[r.SensorCode]; !ok {
//			e.dataMap[r.SensorCode] = make(map[string]map[interface{}]int64)
//			e._rank[r.SensorCode] = make(map[string]siem.ItemList)
//		}
//		if _, ok := e.dataMap[r.SensorCode][category]; !ok {
//			e.dataMap[r.SensorCode][category] = make(map[interface{}]int64)
//			e._rank[r.SensorCode][category] = nil
//		}
//		e.dataMap[r.SensorCode][category][val] += 1
//	}
//
//	// By group
//	if r.IppoolSrcGcode > 0 {
//		if _, ok := e.dataMap[r.IppoolSrcGcode]; !ok {
//			e.dataMap[r.IppoolSrcGcode] = make(map[string]map[interface{}]int64)
//			e._rank[r.IppoolSrcGcode] = make(map[string]siem.ItemList)
//		}
//		if _, ok := e.dataMap[r.IppoolSrcGcode][category]; !ok {
//			e.dataMap[r.IppoolSrcGcode][category] = make(map[interface{}]int64)
//			e._rank[r.IppoolSrcGcode][category] = nil
//		}
//		e.dataMap[r.IppoolSrcGcode][category][val] += 1
//	}
//
//	// To all
//	if _, ok := e.dataMap[ALL]; !ok {
//		e.dataMap[ALL] = make(map[string]map[interface{}]int64)
//		e._rank[ALL] = make(map[string]siem.ItemList)
//	}
//	if _, ok := e.dataMap[ALL][category]; !ok {
//		e.dataMap[ALL][category] = make(map[interface{}]int64)
//		e._rank[ALL][category] = nil
//	}
//	e.dataMap[ALL][category][val] += 1
//
//	// By member
//	if arr, ok := e.memberAssets[r.IppoolSrcGcode]; ok {
//		for _, memberId := range arr {
//			id := memberId * -1
//
//			if _, ok := e.dataMap[id]; !ok {
//				e.dataMap[id] = make(map[string]map[interface{}]int64)
//				e._rank[id] = make(map[string]siem.ItemList)
//			}
//			if _, ok := e.dataMap[id][category]; !ok {
//				e.dataMap[id][category] = make(map[interface{}]int64)
//				e._rank[id][category] = nil
//			}
//			e.dataMap[id][category][val] += 1
//		}
//	}
//
//	return nil
//}
//
//func (e *statsCal) updateMemberAssets() error {
//	query := "select asset_id, member_id from mbr_asset where asset_type = 2"
//	m := make(map[int][]int)
//
//	//	m := make(map[int]map[int]bool)
//	o := orm.NewOrm()
//	var rows []siem.MemberAsset
//	_, err := o.Raw(query).QueryRows(&rows)
//	if err != nil {
//		return err
//	}
//	for _, r := range rows {
//		if _, ok := m[r.AssetId]; !ok {
//			m[r.AssetId] = make([]int, 0)
//		}
//		m[r.AssetId] = append(m[r.AssetId], r.MemberId)
//	}
//
//	rwMutex := new(sync.RWMutex)
//	rwMutex.Lock()
//	e.memberAssets = m
//	rwMutex.Unlock()
//	return nil
//
//}
//
//func determinRanking(m map[interface{}]int64, top int) siem.ItemList {
//	list := make(siem.ItemList, len(m))
//	i := 0
//	for k, v := range m {
//		list[i] = siem.Item{k, v}
//		i++
//	}
//	sort.Sort(sort.Reverse(list))
//	if top > 0 && len(list) > top {
//		return list[0:top]
//	} else {
//		return list
//	}
//}
//
//func (e *statsCal) getRank(groupId int, category string, top int) siem.ItemList {
//	if _, ok := e.rank[groupId]; ok {
//		if list, ok2 := e.rank[groupId][category]; ok2 {
//			if top > 0 && len(list) > top {
//				return list[:top]
//			} else {
//				return list
//			}
//		}
//	}
//	return nil
//}
//
//func (e *statsCal) rankHandler(w http.ResponseWriter, r *http.Request) {
//	vars := mux.Vars(r)
//
//	groupId, _ := strconv.Atoi(vars["groupId"])
//	top, _ := strconv.Atoi(vars["top"])
//
//	list := e.getRank(groupId, vars["category"], top)
//	buf, _ := json.Marshal(list)
//	w.Write(buf)
//}
//
//func (e *statsCal) addHttpApi() {
//	e.router.HandleFunc("/rank/{groupId:-?[0-9]+}/{category}/{top:[0-9]+}", e.rankHandler)
//}
