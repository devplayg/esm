package statistics

import "github.com/gorilla/mux"

type statsCal struct {
	name         string
	router       *mux.Router
	engine       *siem.Engine
	dataMap      DataMap
	_rank        DataRank
	rank         DataRank
	memberAssets map[int][]int
}