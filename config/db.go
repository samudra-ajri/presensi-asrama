package config

import (
	"fmt"

	_ "github.com/lib/pq"
	"gopkg.in/mgo.v2"
)

// database
var DB *mgo.Database

// collections
var Users *mgo.Collection
var Presensi *mgo.Collection
var Sessions *mgo.Collection

func init() {
	// get a mongo sessions
	s, err := mgo.Dial("mongodb://localhost/asrama")
	if err != nil {
		panic(err)
	}

	if err = s.Ping(); err != nil {
		panic(err)
	}

	DB = s.DB("asrama")
	Users = DB.C("users")
	Presensi = DB.C("presensi")
	Sessions = DB.C("sessions")

	fmt.Println("You connected to your mongo database.")
}
