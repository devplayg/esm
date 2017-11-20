package esm

import (
	"time"

	"github.com/devplayg/golibs/orm"
)

type Sensor struct {
	Ip   string
	Port string
}

type MemberAsset struct {
	MemberId int16
	AssetId  int16
}

func getSensors() ([]Sensor, error) {
	var sensors []Sensor
	o := orm.NewOrm()
	_, err := o.Raw("select ip, port from ast_sensor").QueryRows(&sensors)
	return sensors, err
}

type Md5Hash struct {
	Md5      string
	Score    uint8
	Judge    uint8
	Filetype uint8
	Category uint8
	Ext1     uint8
	Ext2     uint8
	Ext3     uint8
	Filesize uint64
	Rdate    time.Time
	Udate    time.Time
}

type DownloadLog struct {
	Rdate          time.Time
	SensorCode     uint16
	IppoolSrcGcode uint16
	IppoolSrcOcode uint16
	TransType      uint8
	SrcIp          uint32
	SrcPort        uint16
	DstIp          uint64
	DstPort        uint16
	DstCountry     string
	Domain         string
	Url            string
	Md5            string
	MailSender     string
	MailRecipient  string
	Filename       string

	//	Rdate      time.Time
	//	Every10Min string
	//	Every1Hour string
	//	SensorCode uint32
	//	SrcGroup   uint16
	//	DstGroup   uint16
	//	TransType  uint8
	//	EventGroup uint8
	//	SrcIp      uint32
	//	DstIp      uint32
	//	DstCountry string
	//	DstDomain string
	//	DstUri string
	//	Md5
	//	EmailSender
	//	MailRecipient
	//	Filename
	//	FileJudge
	//	FileType
	//	FileCategory
	//	Yara
}

type Item struct {
	Key   interface{}
	Count uint32
}

type ItemList []Item

func (p ItemList) Len() int           { return len(p) }
func (p ItemList) Less(i, j int) bool { return p[i].Count < p[j].Count }
func (p ItemList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
