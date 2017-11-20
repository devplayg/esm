package esm

import (
	"github.com/devplayg/golibs/orm"
)

type Sensor struct {
	Ip   string
	Port string
}

func getSensors() ([]Sensor, error) {
	var sensors []Sensor
	o := orm.NewOrm()
	_, err := o.Raw("select ip, port from ast_sensor").QueryRows(&sensors)
	return sensors, err
}
