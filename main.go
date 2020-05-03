// Process a logout which occurs when someone goes to "/logout"

package main

import (
	"fmt"
	"net/http"
	"presensi-asrama/config"
	"strconv"
	"time"

	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2/bson"
)

type user struct {
	FullName string
	UserName string
	Bday     time.Time
	Ds       string
	Klp      string
	Sex      string
	Password []byte
}

type sesi struct {
	Name  int
	Start string
	end   int
}

type presensi struct {
	Pid     string
	Time    time.Time
	Sesi    int
	Generus map[string]string
}

type session struct {
	Sessionid string
	Username  string
}

func main() {
	http.HandleFunc("/", index)
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

	h, m, _ := time.Now().Clock()
	tnow := h*60 + m

	//Asrama sessions
	sesi1 := sesi{1, "08.00", 570}
	sesi2 := sesi{2, "09.45", 675}
	sesi3 := sesi{3, "13.30", 900}
	sesi4 := sesi{4, "20.15", 1305}

	var s sesi
	switch {
	case tnow <= sesi1.end-15:
		s = sesi1
	case inBetween(tnow, sesi1.end-14, sesi2.end):
		s = sesi2
	case inBetween(tnow, sesi2.end+1, sesi3.end):
		s = sesi3
	case inBetween(tnow, sesi3.end+1, sesi4.end):
		s = sesi4
	case tnow > sesi4.end:
		s = sesi1
	}

	// Msg for html-form
	var msg string
	if inBetween(tnow, sesi1.end-120, sesi1.end-16) || inBetween(tnow, sesi2.end-120, sesi2.end) || inBetween(tnow, sesi3.end-120, sesi3.end) || inBetween(tnow, sesi4.end-120, sesi4.end) {
		if (time.Now().Weekday().String() == "Friday") && (inBetween(tnow, sesi2.end-120, sesi2.end)) {
			msg = `khusus hari Jumat ditiadakan.</p><p class="hint-text" style="font-size:20px;">الحمد لله جزاك الله خيرا</p>`
		} else {
			se := s.Name * 335143
			sName := strconv.Itoa(se)
			msg = `klik "Masuk" untuk melakukan presensi.</p><p class="hint-text" style="font-size:20px;">الحمد لله جزاك الله خيرا</p><p class="hint-text"><a href="/asrama?q=` + sName + `"><button type="button" class="btn btn-success btn-lg btn-block">Masuk</button><a></p>`
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
	config.TPL.ExecuteTemplate(w, "index.gohtml", data)
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
		b := req.FormValue("birthday")
		bd, _ := time.Parse("2006-01-02", b)
		ds := req.FormValue("ds")
		kp := req.FormValue("klp")
		s := req.FormValue("sex")
		p := req.FormValue("password")
		// username taken?
		err := config.Users.Find(bson.M{"username": un}).One(&u)
		if err != nil {
			fmt.Println("signup not OK find-user")
		}
		if u.UserName != "" {
			config.TPL.ExecuteTemplate(w, "signup.gohtml", u)
			return
		}

		// create session
		sID := uuid.NewV4()
		c := &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		http.SetCookie(w, c)

		d := session{c.Value, un}
		err = config.Sessions.Insert(d)
		if err != nil {
			fmt.Println("signup not OK insert-sesssion")
		}

		// store user in db Users
		bs, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.MinCost)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		u = user{fn, un, bd, ds, kp, s, bs}
		err = config.Users.Insert(u)
		if err != nil {
			fmt.Println("signup not OK insert-user")
		}
		// redirect
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	config.TPL.ExecuteTemplate(w, "signup.gohtml", nil)
}

func login(w http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	var u user
	// process form submission
	if req.Method == http.MethodPost {
		un := req.FormValue("username")
		p := req.FormValue("password")
		// is there a username?
		err := config.Users.Find(bson.M{"username": un}).One(&u)
		if err != nil {
			fmt.Println("login not OK find-user")
		}
		if u.UserName == "" {
			d := struct {
				Err string
			}{
				"unErr",
			}
			config.TPL.ExecuteTemplate(w, "login.gohtml", d)
			return
		}
		// does the entered password match the stored password?
		err = bcrypt.CompareHashAndPassword(u.Password, []byte(p))
		if err != nil {
			d := struct {
				Err string
				Un  string
			}{
				"pwErr",
				un,
			}
			config.TPL.ExecuteTemplate(w, "login.gohtml", d)
			return
		}
		// create session
		sID := uuid.NewV4()
		c := &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		http.SetCookie(w, c)
		d := session{c.Value, un}
		err = config.Sessions.Insert(d)
		if err != nil {
			fmt.Println("login not OK insert-session")
		}

		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	config.TPL.ExecuteTemplate(w, "login.gohtml", nil)
}

func logout(w http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	c, _ := req.Cookie("session")
	// delete the session
	err := config.Sessions.Remove(bson.M{"sessionid": c.Value})
	if err != nil {
		fmt.Println("Error logout")
	}
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
	fmt.Println(t)
	s, err := strconv.Atoi(v)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	se := s / 335143
	if se > 4 {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	y := time.Now().Year() - u.Bday.Year()
	var cls string
	switch {
	case y < 13:
		cls = "Cabe Rawit"
	case inBetween(y, 13, 15):
		cls = "SMP"
	case inBetween(y, 16, 18):
		cls = "SMA"
	case inBetween(y, 19, 25):
		cls = "Lepas SMA"
	case y > 25:
		cls = "Dewasa"
	}

	g := map[string]string{"name": u.FullName, "class": cls, "ds": u.Ds, "klp": u.Klp, "sex": u.Sex}

	var p presensi
	pID := t.Format("010206") + strconv.Itoa(se) + u.UserName
	// presensi already stored?
	err = config.Presensi.Find(bson.M{"pid": pID}).One(&p)
	if err != nil {
		p = presensi{pID, t, se, g}
		err = config.Presensi.Insert(p)
		if err != nil {
			fmt.Println("insertPresensi not OK presensi-insert")
		}
	}
}

func inBetween(i, min, max int) bool {
	if (i >= min) && (i <= max) {
		return true
	}
	return false
}
