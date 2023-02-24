/*
 *  webapp - Cola web application framework.
 *
 *  Copyright (c) 2019  Priceboro Newport, Inc.  All Rights Reserved.
 *
 */

package webapp

import (
	"github.com/priceboronewport/filestore"
	"github.com/priceboronewport/logger"
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"html"
	"html/template"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type DataStore interface {
	Read(...string) string
	Write(string, string) error
}

type Record map[string]string

type HandlerParams struct {
	Session  string
	Instance string
	Username string
}

type RenderTableParams struct {
	ColClasses map[string]string
	ColLinks   map[string]string
	FilterCols string
	FilterName string
	HeaderRows int
	HiddenCols string
	HtmlCols   string
}

type HandlerFunc func(http.ResponseWriter, *http.Request, HandlerParams)

var DB *sql.DB
var sessions DataStore
var session_values DataStore
var handlers map[string]HandlerFunc
var require_auths map[string]bool
var Config *filestore.FileStore
var data_path string
var permissions DataStore
var user_roles DataStore
var user_values DataStore

const NullUser = "_"

func ConfigFilename(config_path string) string {
	log_prefix := "webapp.ConfigFilename()"
	_, exe_filename := filepath.Split(os.Args[0])
	extension := filepath.Ext(os.Args[0])
	result := config_path + exe_filename + ".conf"
	if extension != "" {
		result = config_path + exe_filename[0:len(exe_filename)-len(extension)]
	}
	logger.Informational(log_prefix, config_path, result)
	return result
}

func Contains(s []string, v string) bool {
	for _, c := range s {
		if c == v {
			return true
		}
	}
	return false
}

func ContentType(filename string) string {
	mime_types := filestore.New(data_path + "mime_types.fs")
	ext := strings.ToLower(filepath.Ext(filename))
	mime_type := ""
	if ext != "" {
		mime_type = mime_types.Read(ext[1:])
	}
	if mime_type == "" {
		f, err := os.Open(filename)
		if err != nil {
			return ""
		}
		defer f.Close()
		buffer := make([]byte, 512)
		n, err := f.Read(buffer)
		if err != nil {
			return ""
		}
		mime_type = http.DetectContentType(buffer[:n])
	}
	return mime_type
}

func DocumentRoot(host string) (result string) {
	host = Config.Read("alias:"+host, host)
	result = Config.Read("document_root:"+host, Config.Read("document_root", "."))
	if result[len(result)-1:] != "/" {
		result += "/"
	}
	return
}

func GetSession(w http.ResponseWriter, r *http.Request) string {
	session := ""
	sysid := Config.Read("sysid")
	c, _ := r.Cookie(sysid + "_session")
	if c != nil {
		session = c.Value
	}
	if len(session) > 0 {
		if sessions.Read(session) == "" {
			session = ""
		}
	}
	if len(session) == 0 {
		for {
			session = fmt.Sprintf("%d", rand.Uint32())
			if sessions.Read(session) == "" {
				break
			}
		}
		sessions.Write(session, NullUser)
		http.SetCookie(w, &http.Cookie{Name: sysid + "_session", Value: session, Path: "/", Expires: time.Now().AddDate(1, 0, 0)})
	}
	return session
}

func ListenAndServe(config_path string) {
	config_filename := ConfigFilename(config_path)
	Config = filestore.New(config_filename)
	logger.Init("./conf/logger.conf")
	log_prefix := "webapp.ListenAndServe()"
	logger.Notice(log_prefix, "Starting", "config_filename="+config_filename)
	if len(require_auths) > 0 {
		if !HandlerExists("", "/login") {
			logger.Notice(log_prefix, "Installing default /login handler")
			Register("", "/login", LoginHandler, false)
		}
		if !HandlerExists("", "/logout") {
			logger.Notice(log_prefix, "Installing default /logout handler")
			Register("", "/logout", LogoutHandler, false)
		}
	}
	rand.Seed(time.Now().UTC().UnixNano())
	data_path = Config.Read("data_path", "./data/")
	sessions = filestore.New(data_path + "sessions.fs")
	session_values = filestore.New(data_path + "session_values.fs")
	permissions = filestore.New(data_path + "permissions.fs")
	user_roles = filestore.New(data_path + "user_roles.fs")
	user_values = filestore.New(data_path + "user_values.fs")
	if _, err := os.Stat(data_path + "sessions.fs"); os.IsNotExist(err) {
		logger.Emergency(log_prefix, data_path+"sessions.fs missing")
	}
	db_type := Config.Read("db_type")
	if db_type != "" {
		logger.Notice(log_prefix, "Connecting to database", db_type)
		var err error
		db_connect := Config.Read("db_connect")
		DB, err = sql.Open(db_type, db_connect)
		if err != nil {
			logger.Emergency(log_prefix, "Database Connect Failed", err.Error(), db_type, db_connect)
		}
		defer DB.Close()
		err = DB.Ping()
		if err != nil {
			logger.Emergency(log_prefix, "Database Ping Failed", err.Error(), db_type, db_connect)
		}
	}
	http.HandleFunc("/", Handler)
	address := Config.Read("address")
	tls_address := Config.Read("tls_address")
	if tls_address != "" {
		tls_cert := Config.Read("tls_cert")
		tls_key := Config.Read("tls_key")
		if address != "" {
			go func() {
				logger.Notice(log_prefix, "Listening TLS", tls_address, tls_cert, tls_key)
				err := http.ListenAndServeTLS(tls_address, tls_cert, tls_key, nil)
				logger.Emergency(log_prefix, "http.ListenAndServeTLS()", err.Error())
			}()
		} else {
			logger.Notice(log_prefix, "Listening TLS", tls_address, tls_cert, tls_key)
			err := http.ListenAndServeTLS(tls_address, tls_cert, tls_key, nil)
			logger.Emergency(log_prefix, "http.ListenAndServeTLS()", err.Error())
		}
	}
	if address != "" {
		logger.Notice(log_prefix, "Listening", address)
		err := http.ListenAndServe(address, nil)
		logger.Emergency(log_prefix, "http.ListenAndServe()", err.Error())
	}
}

func LogError(err error, source string) {
	if err != nil {
		logger.Error(source, err.Error())
	}
}

func Handler(w http.ResponseWriter, r *http.Request) {
	log_prefix := "webapp.Handler()"
	logger.Informational(log_prefix, "Request From: "+r.RemoteAddr, "For: "+r.Host, r.URL.String())
	require_host := Config.Read("require_host")
	if require_host != "" && r.Host != require_host {
		url := "http"
		if r.TLS != nil {
			url += "s"
		}
		url += "://" + require_host + r.URL.String()
		logger.Notice(log_prefix, "Invalid Host", r.Host, "Redirect:", url)
		Redirect(w, r, url)
		return
	}
	if r.TLS == nil && Config.Read("require_tls:"+r.Host) != "" {
		url := "https://" + r.Host + r.URL.String()
		logger.Notice(log_prefix, "TLS Required. Redirect", url)
		Redirect(w, r, url)
		return
	}
	alias := Config.Read("alias:" + r.Host)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	instance := fmt.Sprintf("%s %p", timestamp, &timestamp)
	session := GetSession(w, r)
	username := sessions.Read(session)
	if username == NullUser {
		username = ""
	}
	logger.Informational(log_prefix, "alias="+alias, "instance="+instance, "session="+session, "username="+username)
	if handlers != nil {
		rurl := r.URL.String()
		var candidate_f HandlerFunc
		candidate_f = nil
		candidate_l := 0
		for domain_branch, f := range handlers {
			domain := ""
			branch := ""
			pos := strings.Index(domain_branch, ":")
			if pos > -1 {
				domain = domain_branch[:pos]
				branch = domain_branch[pos+1:]
			} else {
				branch = domain_branch
			}
			if (len(rurl) >= len(branch)) && (rurl[:len(branch)] == branch) && ((r.Host == domain) || (domain == "") || (alias == domain)) {
				if len(branch) > candidate_l {
					logger.Informational(log_prefix, "Handler Selected", "Domain="+domain, "Branch="+branch)
					candidate_f = f
					candidate_l = len(branch)
				}
			}
		}
		if candidate_f != nil {
			if require_auths[fmt.Sprintf("%p", candidate_f)] && username == "" {
				url := "/login?return=" + url.QueryEscape(rurl)
				logger.Notice(log_prefix, "Authentication Required.  Redirect", url)
				Redirect(w, r, url)
				return
			}
			candidate_f(w, r, HandlerParams{Session: session, Instance: instance, Username: username})
			return
		} else {
			logger.Warning(log_prefix, "Ignored", r.URL.String())
			return
		}
	} else {
		logger.Warning(log_prefix, "No handlers")
	}
}

func HandlerExists(query_domain string, query_branch string) bool {
	for domain_branch, _ := range handlers {
		domain := ""
		branch := ""
		pos := strings.Index(domain_branch, ":")
		if pos > -1 {
			domain = domain_branch[:pos]
			branch = domain_branch[pos+1:]
		} else {
			branch = domain_branch
		}
		if domain == query_domain && branch == query_branch {
			return true
		}
	}
	return false
}

func HasPermission(username string, permission string) bool {
	log_prefix := "webapp.HasPermission()"
	logger.Debug(log_prefix, "username:", username, "permission:", permission)
	roles := strings.Split(permissions.Read(permission), ",")
	logger.Debug(log_prefix, "roles", permissions.Read(permission))
	if len(roles) < 1 {
		permissions.Write(permission, "admin")
		roles = append(roles, "admin")
	}
	ur := strings.Split(user_roles.Read(username), ",")
	logger.Debug(log_prefix, "users", user_roles.Read(username))
	for _, r := range roles {
		for _, c := range ur {
			if c == r {
				logger.Debug(log_prefix, "Permission Granted", "permission="+permission, "username="+username, "role="+r)
				return true
			}
		}
	}
	logger.Debug(log_prefix, "Permission Denied", "permission="+permission, "username="+username)
	return false
}

func Break(str string, break_after int, break_str string) (html string) {
	if len(str) <= break_after {
		html = str
	} else {
		html = str[:break_after]
		l := break_after
		i := break_after
		for i < len(str) {
			if str[i] <= ' ' && (l >= break_after) {
				html += break_str
				l = 0
			} else {
				html += str[i : i+1]
			}
			i += 1
			l += 1
		}
	}
	return
}

func IfEmpty(str string, defstr string) string {
	if str == "" {
		return defstr
	}
	return str
}

func Icon(url string) string {
	return "<link rel='icon' href='" + url + "'/><link rel='apple-touch-icon' href='" + url + "'/>"
}

func InstanceValueImport(p HandlerParams, key string) (err error) {
	return InstanceValueWrite(key, UserValuesRead(p.Username, key))
}

func InstanceValueRead(keys ...string) (result string) {
	if len(keys) > 0 {
		query := fmt.Sprintf("select @%s", keys[0])
		rows, err := DB.Query(query)
		LogError(err, "webapp.InstanceValueRead: "+query)
		if err == nil {
			defer rows.Close()
			if rows.Next() {
				rows.Scan(&result)
			}
		}
		if len(keys) > 1 && result == "" {
			result = keys[1]
		}
	}
	return
}

func InstanceValueWrite(key string, value string) (err error) {
	sql := fmt.Sprintf("set @%s=?", key)
	_, err = DB.Exec(sql, value)
	LogError(err, "webapp.InstanceValueWrite: "+sql)
	return
}

type LoginParams struct {
	ReturnURL    string
	ErrorMessage string
}

func LoginHandler(w http.ResponseWriter, r *http.Request, p HandlerParams) {
	log_prefix := "webapp.LoginHandler()"
	r.ParseForm()
	action := r.Form.Get("action")
	if action == "Login" {
		username := strings.ToLower(r.Form.Get("username"))
		password := r.Form.Get("password")
		return_url := IfEmpty(SessionValuesRead(p, "login.return_url"), "/")
		passwords := filestore.New(data_path + "/passwords.fs")
		password_rec := strings.Split(passwords.Read(username), ",")
		var hash string
		if len(password_rec) == 1 && password == password_rec[0] {
			salt := fmt.Sprintf("%d", rand.Uint32())
			h := sha256.New()
			io.WriteString(h, salt+password)
			hash = base64.StdEncoding.EncodeToString(h.Sum(nil))
			passwords.Write(username, hash+","+salt)
			password_rec[0] = hash
		} else {
			if len(password_rec) >= 2 {
				salt := password_rec[1]
				h := sha256.New()
				io.WriteString(h, salt+password)
				hash = base64.StdEncoding.EncodeToString(h.Sum(nil))
			}
		}
		if password_rec[0] == hash && hash != "" && password != "" {
			sessions.Write(p.Session, username)
			Redirect(w, r, return_url)
			logger.Notice(log_prefix, "Login", username)
			return
		}
		logger.Error(log_prefix, "Login Failed", username)
		Render(w, "login.html", LoginParams{ReturnURL: return_url, ErrorMessage: "Login Failed"})
	} else {
		return_url := IfEmpty(r.URL.Query().Get("return"), "/")
		SessionValuesWrite(p, "login.return_url", return_url)
		Render(w, "login.html", LoginParams{ReturnURL: return_url, ErrorMessage: ""})
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request, p HandlerParams) {
	sessions.Write(p.Session, NullUser)
	return_url := r.URL.Query().Get("return")
	if return_url == "" {
		return_url = "/"
	}
	Redirect(w, r, return_url)
}

func Protocol(r *http.Request) (protocol string) {
	if r.TLS != nil {
		protocol = "https://"
	} else {
		protocol = "http://"
	}
	return
}

func Query(sql string) (string, error) {
	log_prefix := "webapp.Query()"
	var result string
	rows, err := DB.Query(sql)
	if err == nil {
		defer rows.Close()
		if rows.Next() {
			err = rows.Scan(&result)
		}
	}
	if err != nil {
		logger.Error(log_prefix, err.Error(), sql)
		return "", err
	}
	return result, nil
}

func QueryRecord(query string) (Record, error) {
	var result Record
	result = make(map[string]string)
	rows, err := DB.Query(query)
	LogError(err, "webapp.QueryRecord: "+query)
	if err == nil {
		defer rows.Close()
		columns, err := rows.Columns()
		if err == nil {
			count := len(columns)
			values := make([]interface{}, count)
			for i := 0; i < count; i++ {
				values[i] = new(sql.RawBytes)
			}
			rows.Next()
			rows.Scan(values...)
			for i, name := range columns {
				result[name] = string(*values[i].(*sql.RawBytes))
			}
		}
	}
	return result, err
}

func Redirect(w http.ResponseWriter, r *http.Request, url string) {
	http.Redirect(w, r, url, http.StatusFound)
}

func Register(domain string, branch string, f HandlerFunc, require_auth bool) {
	if handlers == nil {
		handlers = make(map[string]HandlerFunc)
		require_auths = make(map[string]bool)
	}
	if domain != "" {
		handlers[domain+":"+branch] = f
	} else {
		handlers[branch] = f
	}
	require_auths[fmt.Sprintf("%p", f)] = require_auth
}

func Render(w http.ResponseWriter, template_filename string, render_params interface{}) {
	log_prefix := "webapp.Render()"
	t, err := template.ParseFiles(Config.Read("template_path", "./templates/") + template_filename)
	if t != nil {
		err = t.Execute(w, render_params)
		if err != nil {
			logger.Critical(log_prefix, template_filename, "template.Execute", err.Error())
		}
	} else {
		logger.Critical(log_prefix, template_filename, "template.ParseFiles", err.Error())
	}
}

func RenderIncrementalSearch(id, width, height string) (html string) {
	html += "<input id='" + id + "' onBlur='is_blur(this)' onKeypress='is_change(this)' type='text'/><br/>"
	html += "<div id='" + id + "_pulldown' tabindex='-1' style='height: " + height + "px; width: " + width + "x' class='is_pulldown'></div>"
	return
}

func RenderTable(username string, id string, rows *sql.Rows, p RenderTableParams) string {
	hidden_cols := strings.Split(p.HiddenCols, ",")
	filter_cols := strings.Split(p.FilterCols, ",")
	html_cols := strings.Split(p.HtmlCols, ",")
	result := "<table id='" + id + "' class='default multi_hl sortable'><thead><tr>"
	columns, _ := rows.Columns()
	for _, name := range columns {
		if !Contains(hidden_cols, name) {
			result += "<th"
			if p.ColClasses != nil {
				if p.ColClasses[name] == "" {
					p.ColClasses[name] = p.ColClasses["default"]
				}
				if p.ColClasses[name] != "" {
					result += " class='" + p.ColClasses[name] + "'"
				}
			}
			result += " onClick='tsrt.Sort(this)'>" + html.EscapeString(name) + "</th>"
		}
	}
	result += "</tr>"
	hook_apply := false
	if len(filter_cols) > 1 {
		result += "<tr>"
		first_col := true
		for i, name := range columns {
			if !Contains(hidden_cols, name) {
				result += "<td class='filter'>"
				if first_col {
					result += "<div style='white-space: nowrap; text-align: center;'>"
					result += "<button class='apply ui_hint' id='" + id + "_apply' onClick='return tfltr.Apply(this)'><span class='ui_hinttext'>Apply Filter</span></button>"
					result += "<button class='reset ui_hint' onClick='return tfltr.Reset(this)'><span class='ui_hinttext'>Clear Filter</span></button>"
					result += "</div>"
					first_col = false
				}
				if Contains(filter_cols, name) {
					value := UserValuesRead(username, fmt.Sprintf("tfltr.%s.%d", id, i))
					if value != "" {
						hook_apply = true
					}
					result += "<input onKeyPress='return tfltr.KeyPress(this,event)' type='text' size='2' value='" + html.EscapeString(value) + "'/>"
				}
				result += "</td>"
			}
		}
		result += "</tr>"
	}
	count := len(columns)
	col_values := make([]string, count)
	values := make([]interface{}, count)
	value_ptrs := make([]interface{}, count)
	row_count := 0
	for rows.Next() {
		if row_count == p.HeaderRows {
			result += "</thead><tbody>"
		}
		row_count++
		result += "<tr onClick='thl.Toggle(this)'>"
		for i, _ := range columns {
			value_ptrs[i] = &values[i]
		}
		rows.Scan(value_ptrs...)
		for i, name := range columns {
			val := values[i]
			s := ""
			b, ok := val.([]byte)
			if ok {
				s = string(b)
			}
			col_values[i] = s
			if !Contains(hidden_cols, name) {
				result += "<td"
				var classes string
				if p.ColClasses != nil {
					classes = p.ColClasses[name]
				}
				if len(s) > 1 && (s[0:1] == "-" || s[1:2] == "-") {
					if classes != "" {
						classes += " "
					}
					classes += "neg"
				}
				if classes != "" {
					result += " class='" + classes + "'"
				}
				result += ">"
				if p.ColLinks != nil && p.ColLinks[name] != "" && row_count > p.HeaderRows {
					link_url := strings.Replace(p.ColLinks[name], "{}", url.QueryEscape(s), -1)
					for j := 0; j < i; j++ {
						link_url = strings.Replace(link_url, "{"+strconv.Itoa(j)+"}", url.QueryEscape(col_values[j]), -1)
					}
					if (len(s) > 9) && (s[2:3] == "/") {
						result += "<!-- " + html.EscapeString(s[6:10]+s[0:2]+s[3:5]) + " --><a href='" + link_url + "'>"
					} else {
						result += "<!-- " + html.EscapeString(s) + " --><a href='" + link_url + "'>"
					}
				}
				if Contains(html_cols, name) {
					result += s
				} else {
					result += html.EscapeString(s)
				}
				if p.ColLinks != nil && p.ColLinks[name] != "" {
					result += "</a>"
				}
				result += "</td>"
			}
		}
		result += "</tr>"
	}
	if row_count < p.HeaderRows {
		result += "</thead>"
	}
	result += "</tbody></table>"
	if hook_apply {
		result += "<script type='text/javascript'>document.getElementById(\"" + id + "_apply\").click();</script>"
	}
	return result
}

func Script(url string) string {
	return "<script type='text/javascript' src='" + url + "'></script>"
}

func SessionValuesRead(p HandlerParams, keys ...string) (result string) {
	if len(keys) > 0 {
		result = session_values.Read(p.Session + "_" + keys[0])
		if len(keys) > 1 && result == "" {
			result = keys[1]
		}
	}
	return
}

func SessionValuesWrite(p HandlerParams, key string, value string) (err error) {
	session_values.Write(p.Session+"_"+key, value)
	return nil
}

func StaticHandler(w http.ResponseWriter, r *http.Request, p HandlerParams) {
	log_prefix := "webapp.StaticHandler()"
	document_root := DocumentRoot(r.Host)
	filename := Trunc(r.URL.String()[1:], "?")
	if filename == "" {
		filename = document_root + "index.html"
	} else {
		filename = document_root + filename
	}
	mime_type := ContentType(filename)
	logger.Debug(log_prefix, "filename="+filename, "mime_type="+mime_type)
	f, err := ioutil.ReadFile(filename)
	if (err != nil) || (mime_type == "") {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "Not Found")
		logger.Error(log_prefix, "404 - Not Found", filename)
		return
	}
	b := bytes.NewBuffer(f)
	w.Header().Set("Content-type", mime_type)
	b.WriteTo(w)
}

func Stylesheet(url string) string {
	return "<link href='" + url + "' type='text/css' rel='stylesheet'/>"
}

func Trunc(s string, d string) string {
	if idx := strings.Index(s, d); idx != -1 {
		return s[:idx]
	}
	return s
}

func UrlPath(r *http.Request, index int) string {
	url_path := strings.Split(strings.Split(r.URL.String()[1:], "?")[0], "/")
	if len(url_path) > index {
		result, _ := url.QueryUnescape(url_path[index])
		return result
	}
	return ""
}

func User(username string) Record {
	users := filestore.New(data_path + "/users.fs")
	result := make(Record)
	user_rec := strings.Split(users.Read(username), ",")
	for i, v := range user_rec {
		switch i {
		case 0:
			result["first_name"] = v
		case 1:
			result["last_name"] = v
		case 2:
			result["email"] = v
		}
	}
	return result
}

func UserValuesRead(username string, keys ...string) (result string) {
	if len(keys) > 0 {
		result = user_values.Read(username + ":" + keys[0])
		if len(keys) > 1 && result == "" {
			result = keys[1]
		}
	}
	return
}

func UserValuesWrite(username string, key string, value string) (err error) {
	user_values.Write(username+":"+key, value)
	return nil
}
