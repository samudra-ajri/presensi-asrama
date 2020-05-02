// Process a logout which occurs when someone goes to "/logout"

package main

import (
	"fmt"
	"net/http"
	"text/template"
	"time"

	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type user struct {
	FullName string
	UserName string
	Bday     string
	Ds       string
	Klp      string
	Sex      string
	Password []byte
}

type sesi struct {
	Name  string
	Start string
	end   float64
}

type presensi struct {
	Time    time.Time
	Sesi    string
	Generus map[string]string
}

var tpl *template.Template
var dbUsers = map[string]user{}        // user ID, user
var dbSessions = map[string]string{}   // session ID, user ID
var dbPresensi = map[string]presensi{} // session ID, user ID

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
	bs, _ := bcrypt.GenerateFromPassword([]byte("asd"), bcrypt.MinCost)
	dbUsers["asd"] = user{"asd", "asd", "12/12/1996", "testDs", "testKlp", "l", bs}
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/bar", bar)
	http.HandleFunc("/asrama", asrama)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.ListenAndServe(":8080", nil)
}

func asrama(w http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}
	go insertPresensi(w, req)
	http.Redirect(w, req, "https://asrama.walibarokah.org/", http.StatusSeeOther)
}

func index(w http.ResponseWriter, req *http.Request) {
	u := getUser(w, req)
	if !alreadyLoggedIn(req) {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	// h, m, _ := time.Now().Clock()
	// tnow := float64(h) + float64(m)/60.0

	//Asrama sessions
	sesi1 := sesi{"1", "08.00", 9.0 + 30.0/60.0}
	sesi2 := sesi{"2", "09.45", 11.0 + 15.0/60.0}
	sesi3 := sesi{"3", "13.30", 15.0}
	sesi4 := sesi{"4", "20.15", 21.0 + 45.0/60.0}

	tnow := sesi4.end - 0.1

	var s sesi
	switch {
	case tnow <= sesi1.end-0.25:
		s = sesi1
	case inBetween(tnow, sesi1.end-0.24, sesi2.end):
		s = sesi2
	case inBetween(tnow, sesi2.end+0.01, sesi3.end):
		s = sesi3
	case inBetween(tnow, sesi3.end+0.01, sesi4.end):
		s = sesi4
	case tnow > sesi4.end:
		s = sesi1
	}

	// Msg for html-form
	var msg string
	if inBetween(tnow, sesi1.end-2, sesi1.end-0.26) || inBetween(tnow, sesi2.end-2, sesi2.end) || inBetween(tnow, sesi3.end-2, sesi3.end) || inBetween(tnow, sesi4.end-2, sesi4.end) {
		if (time.Now().Weekday().String() == "Friday") && (inBetween(tnow, sesi2.end-2, sesi2.end)) {
			msg = `khusus hari Jumat ditiadakan.</p><p class="hint-text" style="font-size:20px;">الحمد لله جزاك الله خيرا</p>`
		} else {
			msg = `klik "Masuk" untuk melakukan presensi.</p><p class="hint-text" style="font-size:20px;">الحمد لله جزاك الله خيرا</p><p class="hint-text"><a href="/asrama?q=` + s.Name + `"><button type="button" class="btn btn-success btn-lg btn-block">Masuk</button><a></p>`
		}
	} else {
		msg = `daftar hadir dibuka 30 menit sebelum sesi dimulai. </p><br><p class="hint-text" style="font-size:20px;">الحمد لله جزاك الله خيرا</p>`
	}

	data := struct {
		Name user
		Sesi sesi
		Msg  string
	}{
		u,
		s,
		msg,
	}
	fmt.Println(dbPresensi)
	tpl.ExecuteTemplate(w, "index.gohtml", data)
}

func bar(w http.ResponseWriter, req *http.Request) {
	u := getUser(w, req)
	if !alreadyLoggedIn(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(w, "bar.gohtml", u)
}

func signup(w http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	var u user
	// process form submission
	if req.Method == http.MethodPost {
		// get form values
		fn := req.FormValue("fullname")
		un := req.FormValue("username")
		bd := req.FormValue("birthday")
		ds := req.FormValue("ds")
		kp := req.FormValue("klp")
		s := req.FormValue("sex")
		p := req.FormValue("password")
		// username taken?
		if _, ok := dbUsers[un]; ok {
			u = user{fn, un, bd, ds, kp, s, nil}
			tpl.ExecuteTemplate(w, "signup.gohtml", u)
			return
		}
		// create session
		sID, _ := uuid.NewV4()
		c := &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		http.SetCookie(w, c)
		dbSessions[c.Value] = un
		// store user in dbUsers
		bs, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.MinCost)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		u = user{fn, un, bd, ds, kp, s, bs}
		dbUsers[un] = u
		// redirect
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(w, "signup.gohtml", nil)
}

func login(w http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	// var u user
	// process form submission
	if req.Method == http.MethodPost {
		un := req.FormValue("username")
		p := req.FormValue("password")
		// is there a username?
		u, ok := dbUsers[un]
		if !ok {
			d := struct {
				Err string
			}{
				"unErr",
			}
			tpl.ExecuteTemplate(w, "login.gohtml", d)
			return
		}
		// does the entered password match the stored password?
		err := bcrypt.CompareHashAndPassword(u.Password, []byte(p))
		if err != nil {
			d := struct {
				Err string
				Un  string
			}{
				"pwErr",
				un,
			}
			tpl.ExecuteTemplate(w, "login.gohtml", d)
			return
		}
		// create session
		sID, _ := uuid.NewV4()
		c := &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		http.SetCookie(w, c)
		dbSessions[c.Value] = un
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	tpl.ExecuteTemplate(w, "login.gohtml", nil)
}

func logout(w http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	c, _ := req.Cookie("session")
	// delete the session
	delete(dbSessions, c.Value)
	// remove the cookie
	c = &http.Cookie{
		Name:   "session",
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(w, c)

	http.Redirect(w, req, "/login", http.StatusSeeOther)
}

func insertPresensi(w http.ResponseWriter, req *http.Request) {
	v := req.FormValue("q")
	u := getUser(w, req)

	t := time.Now()
	s := v
	g := map[string]string{"name": u.FullName, "bday": u.Bday, "ds": u.Ds, "klp": u.Klp, "sex": u.Sex}

	var p presensi
	pID := t.Format("010206") + s + u.UserName
	if _, ok := dbPresensi[pID]; !ok {
		p = presensi{t, s, g}
		dbPresensi[pID] = p
	}
}

func inBetween(i, min, max float64) bool {
	if (i >= min) && (i <= max) {
		return true
	}
	return false
}
