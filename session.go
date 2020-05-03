package main

import (
	"fmt"
	"net/http"

	"presensi-asrama/config"

	uuid "github.com/satori/go.uuid"
	"gopkg.in/mgo.v2/bson"
)

func getUser(w http.ResponseWriter, req *http.Request) user {
	// get cookie
	c, err := req.Cookie("session")
	if err != nil {
		sID := uuid.NewV4()
		c = &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}

	}
	http.SetCookie(w, c)

	// if the user exists already, get user
	var se session
	err = config.Sessions.Find(bson.M{"sessionid": c.Value}).One(&se)
	if err != nil {
		fmt.Println("session getuser not OK sessions-find")
	}

	var u user
	err = config.Users.Find(bson.M{"username": se.Username}).One(&u)
	if err != nil {
		fmt.Println("session getuser not OK users-find")
	}
	return u
}

func alreadyLoggedIn(req *http.Request) bool {
	c, err := req.Cookie("session")
	if err != nil {
		return false
	}

	var se session
	err = config.Sessions.Find(bson.M{"sessionid": c.Value}).One(&se)
	if err != nil {
		fmt.Println("session alreadylogin not OK sessions-find")
		return false
	}

	var u user
	err = config.Users.Find(bson.M{"username": se.Username}).One(&u)
	if err != nil {
		fmt.Println("session alreadylogin not OK users-find")
		return false
	}
	return true
}
