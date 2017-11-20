package stats

import (
	//	"sort"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/devplayg/esm"
	"github.com/devplayg/golibs/orm"
	log "github.com/sirupsen/logrus"
)

var (
	md5Map    sync.Map
	statsRank StatsRank
	t         time.Time
)

type StatsMap map[int32]map[string]map[interface{}]uint32
type StatsRank map[int32]map[string]esm.ItemList

type Statist struct {
	interval     int64
	statsMap     StatsMap
	memberAssets map[int16]map[int16]bool
}

func NewStatist(interval int64) *Statist {
	md5Map = sync.Map{}

	return &Statist{
		interval: interval,
	}
}

func (e *Statist) Start(errChan chan<- error) error {
	go func() {
		for {
			t = time.Now()

			//						if err := updateMd5Map(); err != nil {
			//				errChan <- nil
			//			}

			e.statsMap = make(StatsMap)
			e.updateMembersAssets()
			if err := e.generateStats(); err != nil {
				errChan <- err
			}
			//			genStats("download")
			//			genStats("detection")

			// Sleep
			log.Debugf("Sleep %3.1fs", (time.Duration(e.interval) * time.Millisecond).Seconds())
			time.Sleep(time.Duration(e.interval) * time.Millisecond)
		}
	}()

	return nil
}

func (e *Statist) generateStats() error {
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
	sdate := t.Format("2006-01-02") + " 00:00:00"
	edate := t.Format("2006-01-02") + " 23:59:59"

	//	var rows []esm.DownloadLog
	o := orm.NewOrm()
	//	_, err := o.Raw(query, sdate, edate).QueryRows(&rows)
	//	if err != nil {
	//		return err
	//	}

	//	//	statsIp := make(map[interface{}]uint32)
	//	//	statsMd5 := make(map[interface{}]uint32)
	//	for _, r := range rows {
	//		e.addToStats(r, "src_ip")
	//		//		statsIp[r.SrcIp] += 1
	//		//		statsMd5[r.Md5] += 1
	//	}

	var rows []orm.Params
	_, err := o.Raw(query, sdate, edate).Values(&rows)
	if err != nil {
		return err
	}

	for _, r := range rows {
		spew.Dump(r)
		//		e.addToStats(r, "src_ip")

	}

	//	if err == nil && num > 0 {
	//		fmt.Println(maps[0]["user_name"]) // slene
	//	}

	return nil
}

func (e *Statist) addToStats(r esm.DownloadLog, category string) error {
	if r.SensorCode > 0 {
		//		if _, ok := e.statsMap[r.SensorCode]; !ok {
		//			e.statsMap[(int)r.SensorCode] := nil
		//												e.statsMap[r.SensorCode] := map[string]interface{}
		//		}
	}

	return nil
}

func (e *Statist) updateMembersAssets() error {
	query := "select member_id, asset_id from mbr_asset where asset_type = 2"
	m := make(map[int16]map[int16]bool)
	var rows []esm.MemberAsset
	o := orm.NewOrm()
	_, err := o.Raw(query).QueryRows(&rows)
	if err != nil {
		return err
	}

	for _, r := range rows {
		if _, ok := m[r.MemberId]; !ok {
			m[r.MemberId] = make(map[int16]bool)
		}
		m[r.MemberId][r.AssetId] = true
	}
	var rwMutex = new(sync.RWMutex)
	rwMutex.Lock()
	e.memberAssets = m
	rwMutex.Unlock()
	return nil
}

//func updateMd5Map() error {
//	query := `
//		select  md5,
//		        score,
//		        filetype,
//		        category,
//		        ext1,
//		        ext2,
//		        ext3,
//		        filesize,
//		        rdate,
//		        udate ,
//				case
//					when score = 100 then 1
//					when score < 100 and score >= 40 then 2
//					else 3
//				end judge
//		from pol_file_md5
//	`
//	var rows []esm.Md5Hash
//	o := orm.NewOrm()
//	_, err := o.Raw(query).QueryRows(&rows)
//	if err != nil {
//		return err
//	}

//	for _, r := range rows {
//		md5Map.LoadOrStore(r.Md5, r)
//	}
//	return nil
//}

//func genStats(key string) error {
//	query := `
//			select 	rdate,
//					(sensor_code + 100000) sensor_code,
//					trans_type,
//					ippool_src_gcode,
//					ippool_src_ocode,
//					session_id,
//					src_ip,
//					src_port,
//					src_country,
//					dst_ip,
//					dst_port,
//					dst_country,
//					domain,
//					url,
//					filesize,
//					filename,
//					md5,
//					mail_sender,
//					mail_recipient
//			from log_event_filetrans
//			where rdate >= ? and rdate <= ?
//		`
//	sdate := t.Format("2006-01-02") + " 00:00:00"
//	edate := t.Format("2006-01-02") + " 23:59:59"

//	var rows []esm.DownloadLog
//	o := orm.NewOrm()
//	_, err := o.Raw(query, sdate, edate).QueryRows(&rows)
//	if err != nil {
//		return err
//	}

//	//	stats := make(map[string]ItemList)
//	//	statsIp := make(map[interface{}]uint32)
//	//	statsMd5 := make(map[interface{}]uint32)
//	//	members := map[int]map[int]bool{
//	//		3: {
//	//			1: true,
//	//			2: true,
//	//		},
//	//	}
//	//	spew.Dump(members)

//	for _, r := range rows {
//		spew.Dump(r)
//		//		statsIp[r.SrcIp] += 1
//		//		statsMd5[r.Md5] += 1
//	}
//	// -1 / "srcip", ip, count

//	stats := make(StatsMap)
//	//	rankByCount(statsIp, 5)
//	//	rankByCount(statsMd5, 5)
//	spew.Dump(stats)

//	return nil
//}

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

//func rankByWordCount(wordFrequencies map[string]int) PairList{
//  pl := make(PairList, len(wordFrequencies))
//  i := 0
//  for k, v := range wordFrequencies {
//    pl[i] = Pair{k, v}
//    i++
//  }
//  sort.Sort(sort.Reverse(pl))
//  return pl
//}

//type Pair struct {
//  Key string
//  Value int
//}

//type PairList []Pair

//func (p PairList) Len() int { return len(p) }
//func (p PairList) Less(i, j int) bool { return p[i].Value < p[j].Value }
//func (p PairList) Swap(i, j int){ p[i], p[j] = p[j], p[i] }
