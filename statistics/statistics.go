package statistics

import (
	"github.com/devplayg/siem"
	"github.com/gorilla/mux"
	"sort"
)

const (
	ALL = -1
)

type DataMap map[int]map[string]map[interface{}]int64 // Code / Category / Key / Count
type DataRank map[int]map[string]siem.ItemList        // Code / Category / Key / Ranking
type StatsCalculator interface {
	Start() error
	GetName() string
}

type Stats struct {
	name   string
	Engine *siem.Engine
	Router *mux.Router
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
