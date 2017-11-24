package stats

import (
	"sort"
	"sync"
	"time"

	"github.com/devplayg/golibs/orm"
	"github.com/devplayg/siem"
	_ "github.com/go-sql-driver/mysql"
	log "github.com/sirupsen/logrus"
)

const (
	ALL = -1
)

var (
	md5Map    sync.Map
	statsRank StatsRank
)

type StatsMap map[int]map[string]map[interface{}]int64
type StatsRank map[int]map[string]siem.ItemList

type Statist struct {
	interval       int64
	statsMap       StatsMap
	statsRank      StatsRank
	membersByAsset map[int][]int
	top            int
}

func NewStatist(interval int64) *Statist {
	md5Map = sync.Map{}

	return &Statist{
		interval: interval,
		top:      10,
	}
}

func (e *Statist) Start(errChan chan<- error) error {
	go func() {
		for {
			e.statsMap = make(StatsMap)
			e.statsRank = make(StatsRank)
			if err := e.updateMembersAssets(); err != nil {
				errChan <- err
			}
			if err := e.generateStats(); err != nil {
				errChan <- err
			}

			rwMutex := new(sync.RWMutex)
			rwMutex.Lock()
			statsRank = e.statsRank
			rwMutex.Unlock()

			// Sleep
			log.Debugf("Sleep %3.1fs", (time.Duration(e.interval) * time.Millisecond).Seconds())
			time.Sleep(time.Duration(e.interval) * time.Millisecond)
		}
	}()

	return nil
}

func (e *Statist) generateStats() error {
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
		for category, _ := range m1 {
			e.statsRank[id][category] = rankByCount(m1[category], e.top)
		}
	}
	t4 := time.Now()
	log.Infof("Query=%3.1f, Statistics=%3.1f, Ranking=%3.1f", t2.Sub(t1).Seconds(), t3.Sub(t2).Seconds(), t4.Sub(t3).Seconds())

	return nil
}

func (e *Statist) addToStats(r siem.DownloadLog, category string, val interface{}) error {

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

func (e *Statist) updateMembersAssets() error {
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

func GetRank(groupId int, category string, top int) siem.ItemList {
	if _, ok := statsRank[groupId]; ok {
		if list, ok2 := statsRank[groupId][category]; ok2 {
			return list
		}
	}
	return nil
}
