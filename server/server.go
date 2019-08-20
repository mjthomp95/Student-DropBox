// Author: jliebowf
// Date: Spring 2015

// SANITIZE Input
package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"os"
	"time"
	//"syscall"
	"strconv"
	// "container/list"
	"encoding/binary"
	"golang.org/x/crypto/bcrypt"
	"net/smtp"
	"regexp"

	"../email"
	"../internal"
	"../lib/support/rpc"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	_ "github.com/mattn/go-sqlite3"
	"path/filepath"
	"strings"
	// "text/template"
)

//TODO: make server struct and redesign handler functions to return http.HandlerFunc

type dbServer struct {
	filesdb *sql.DB
	baseDir string
}

var serverDBs dbServer
var smtpPassword string
var FILE_LIMIT int = 200

func main() {
	var reset bool
	var baseDir, listenAddr string
	//TODO: use flag package to do --reset parsing
	switch {
	case len(os.Args) == 2 && os.Args[1] == "--reset":
		reset = true
	case len(os.Args) == 3 && (len(os.Args[1]) == 0 || os.Args[1][0] != '-'):
		baseDir = os.Args[1]
		listenAddr = os.Args[2]
	default:
		fmt.Fprintf(os.Stderr, "Usage: %v [--reset | <base-dir> <listen-address>]\n", os.Args[0])
		os.Exit(0)
	}

	// These are here to suppress "variable not used" errors.
	// In your implementation, you must actually use them!

	if reset {
		os.Remove("./AllFiles")
		os.Remove("./db")
		os.Mkdir("./AllFiles", 0740)
		os.Mkdir("./db", 0740)
		serverDBs.filesdb = createNewServer()
		os.Exit(0)
	}

	mrand.Seed(time.Now().UnixNano())
	dbs, errs := sql.Open("sqlite3", baseDir+"/db/dropbox.db")
	if errs != nil {
		panic(errs)
	}
	//Check to make sure Database Connection worked
	_, errs = dbs.Exec("SELECT 1")
	if errs != nil {
		panic(errs)
	}
	serverDBs.filesdb = dbs
	serverDBs.baseDir = baseDir

	makeNewTables(serverDBs.filesdb)
	//Cookie Check to make sure all cookie in database are valid
	serverDBs.checkCookies()
	//Password for email account to send verification emails.
	smtpPassword = email.DecryptPassword(baseDir)
	//Email sent to verify password works
	errs = serverDBs.send("@gmail.com", -1, "Server Verification") //Add a email to use
	if errs != nil {
		panic(errs)
	}

	fmt.Println()
	fmt.Println("SMTP Password Set")

	// This code is meant as an example of how to use
	// our framework, not as stencil code. It is not
	// meant as a suggestion of how you should write
	// your application.

	//TODO: Make wrapper for login Handler
	//You can make a function that returns the necessary function
	rpc.RegisterHandler("upload", uploadHandler)
	rpc.RegisterHandler("download", downloadHandler)
	rpc.RegisterHandler("list", listHandler)
	rpc.RegisterHandler("mkdir", mkdirHandler)
	rpc.RegisterHandler("remove", removeHandler)
	rpc.RegisterHandler("share", shareHandler)
	rpc.RegisterHandler("rm_share", rmShareHandler)
	rpc.RegisterHandler("show_shares", showShareHandler)
	rpc.RegisterHandler("delCheck", delCheckHandler)
	rpc.RegisterHandler("delAccount", delAccountHandler)
	rpc.RegisterHandler("show_share", showShareHandler)
	//rpc.RegisterHandler("pwd", pwdHandler)
	rpc.RegisterHandler("cd", cdHandler)
	rpc.RegisterHandler("loginCheck", loginCheckHandler)
	rpc.RegisterHandler("login", loginHandler)
	rpc.RegisterHandler("logout", logoutHandler)
	rpc.RegisterHandler("signup", signupHandler)
	rpc.RegisterHandler("check", checkHandler)
	rpc.RegisterFinalizer(finalizer)
	err := rpc.RunServer(listenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not run server: %v\n", err)
		os.Exit(1)
	}
}

/*send: emails a validation number
Variables:
	Email: email address to send message to
	Validator: The number used to validate
	Body: A short message to add to email
Return: returns an error object. Nil if successful
*/
func (server dbServer) send(email string, validator int, body string) error {
	from := "dropboxsmtp@gmail.com"

	msg := "From: " + from + "\n" +
		"To: " + email + "\n" +
		"Subject: Validation\n\n" + body +
		"Your validation number is: " + strconv.Itoa(validator)

	err := smtp.SendMail("smtp.gmail.com:587",
		smtp.PlainAuth("", from, smtpPassword, "smtp.gmail.com"),
		from, []string{email}, []byte(msg))

	if err != nil {
		fmt.Printf("smtp error: %v\n", err.Error())
		return err
	}
	fmt.Println("Email Sent")
	return nil
}

// This is called by the server when reset is set to call
// deletePrevTables and MakeNewTables
func createNewServer() *sql.DB {
	db, err := sql.Open("sqlite3", "./db/dropbox.db")
	if err != nil {
		panic(err)
	}
	if db == nil {
		panic("open db nil!")
	}
	deletePrevTables(db)
	makeNewTables(db)
	return db
}

// This deletes all the previously existing tables in the database
func deletePrevTables(db *sql.DB) {
	//dropping files table
	sql := "DROP TABLE IF EXISTS FILES"
	_, err := db.Exec(sql)
	if err != nil {
		panic(err)
	}

	//dropping dirs table
	sql = "DROP TABLE IF EXISTS DIRS"
	_, err = db.Exec(sql)
	if err != nil {
		panic(err)
	}

	//dropping accounts table
	sql = "DROP TABLE IF EXISTS ACCOUNTS"
	_, err = db.Exec(sql)
	if err != nil {
		panic(err)
	}

	//dropping cookies table
	sql = "DROP TABLE IF EXISTS COOKIES"
	_, err = db.Exec(sql)
	if err != nil {
		panic(err)
	}
}

// This makes new tables in the given databas
func makeNewTables(db *sql.DB) {
	sql := `
		CREATE TABLE IF NOT EXISTS FILES(
			username TEXT ,
			rootuser TEXT,
			superpath TEXT,
			filehash TEXT,
			filename TEXT,
			read INTEGER,
			write INTEGER,
			PRIMARY KEY(username, rootuser, superpath, filename)
		);`

	_, err := db.Exec(sql)
	if err != nil {
		panic(err)
	}

	sql = `
			CREATE TABLE IF NOT EXISTS DIRS(
				username TEXT P,
				superpath TEXT,
				filename TEXT,
				PRIMARY KEY(username, superpath, filename)
			);`

	_, err = db.Exec(sql)
	if err != nil {
		panic(err)
	}

	sql = `
			CREATE TABLE IF NOT EXISTS ACCOUNTS(
				username TEXT PRIMARY KEY,
				email TEXT UNIQUE NOT NULL,
				password TEXT NOT NULL,
				validation INT,
				storagetot INT NOT NULL
			);`

	_, err = db.Exec(sql)
	if err != nil {
		panic(err)
	}

	sql = `
			CREATE TABLE IF NOT EXISTS COOKIES(
				cookie TEXT PRIMARY KEY,
				username TEXT UNIQUE NOT NULL, 
				expire DATETIME NOT NULL
			);`

	_, err = db.Exec(sql)
	if err != nil {
		panic(err)
	}

	sql = `CREATE TABLE IF NOT EXISTS VALIDATIONS(
				username TEXT PRIMARY KEY,
				email TEXT UNIQUE NOT NULL,
				validation INT NOT NULL);`
	_, err = db.Exec(sql)
	if err != nil {
		panic(err)
	}

	sql = `DELETE FROM validations;`
	_, err = db.Exec(sql)
	if err != nil {
		panic(err)
	}

}

/*checkCookies: makes sure all cookies in the database are valid*/
func (server dbServer) checkCookies() {
	//Deletes all cookies that are expired
	sql := "DELETE FROM cookies WHERE expire < datetime('now')"
	_, err := server.filesdb.Exec(sql)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Delete Cookies:%v\n", err.Error())
	}
	sql = "SELECT cookie, expire FROM cookies"
	rows, er := server.filesdb.Query(sql)
	if er != nil {
		fmt.Fprintf(os.Stderr, "Delete Cookies:%v\n", err.Error())
		return
	}
	defer rows.Close()
	//Sets up goroutines that will delete the cookie once their time expires
	for rows.Next() {
		var expire string
		var cookie string
		if err := rows.Scan(&cookie, &expire); err != nil {
			fmt.Fprintf(os.Stderr, "Error Scanning: %v\n", err.Error())
			continue
		}
		expireTime, err := time.Parse(time.RFC3339, expire)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Trouble Parsing Time: %v\n", err.Error())
			server.deleteCookie(cookie)
			continue
		}
		time.AfterFunc(time.Until(expireTime), func() { server.deleteCookie(cookie) })
	}
	if err := rows.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error in Rows: %v\n", err.Error())
	}

}

/*hashAndSalt: takes a password and hashes and salts it
Variables:
	password: the password to be hashed and salted
Return: returns the hashed password in string form*/

func hashAndSalt(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Generating Password Hash Error: %v\n", err.Error())
	}

	return string(hash)
}

/*checkPassword: compares the a hashed password to a given password to see if they are the same
Variables:
	hashedPassword: the hashed password to be compared
	password: the password to be compared to the hashed password
Return: a bool value. true if they password is the same, false otherwise.*/
func checkPassword(hashedPassword string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error in Password Check: %v\n", err.Error())
		return false
	}

	return true
}

/*createRandId: creates a random byte array
Variables:
	length: the length of the byte array to create
Return: returns the randomly created byte array*/
func createRandId(length int) []byte {
	random := make([]byte, length)
	if _, err := rand.Reader.Read(random); err != nil {
		return []byte{}
	}
	return random
}

/*is_login: checks to see if a cookie is valid
Variables:
	cookie: the cookie to be tested if it is valid
Return: returns the username associated with the cookie or "" if not valid*/
func (server dbServer) is_login(cookie string) string {
	var username string
	err := server.filesdb.QueryRow("SELECT username FROM cookies WHERE cookie=?", cookie).Scan(&username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cookie Query Error: %v\n", err.Error())
		return ""
	}
	return username
}

/*deleteCookie: invalidates a cookie in the database
Variables:
	cookie: the cookie to be invalidated*/

func (server dbServer) deleteCookie(cookie string) {
	server.filesdb.Exec("DELETE FROM cookies WHERE cookie=?", cookie)
}

/*checkHandler: checks to see if a username and/or email are in use already and after sends a verification number to the email.
Variables:
	username: the username to check
	email: the email to check
Return: gives a message if there is any problem or "" if everything checks out.*/
func checkHandler(username string, email string) string {
	re := regexp.MustCompile("^[a-zA-Z0-9]+$")
	if !(re.MatchString(username)) {
		return "Only Alphanumeric Characters"
	}
	//to check if username exists in database
	err := serverDBs.filesdb.QueryRow("SELECT 1 FROM accounts WHERE username=?", username).Scan(nil)
	if err != sql.ErrNoRows {
		return "Username already in use"
	}
	//to check if email exists in database
	err = serverDBs.filesdb.QueryRow("SELECT 1 FROM accounts WHERE email=?", email).Scan(nil)
	if err != sql.ErrNoRows {
		return "Email already in use"
	}
	//removes any previous attempts with this username or email to validate
	_, err = serverDBs.filesdb.Exec("DELETE FROM validations WHERE username=? OR email=?", username, email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Validation Setup Error: %v\n", err.Error())
		return "Validation Setup Error"
	}
	validator := mrand.Int()
	_, err = serverDBs.filesdb.Exec("INSERT INTO validations(username, email, validation) VALUES(?, ?, ?)", username, email, validator)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Validation Insertion Error: %v\n", err.Error())
		return "Validation Setup Error"
	}
	//send email
	err = serverDBs.send(email, validator, "Signup Validation\n")
	if err != nil {
		//email wasn't sent correctly so no one will ever get the verification. Need to delete
		serverDBs.filesdb.Exec("DELETE FROM validations WHERE username=?", username)
		fmt.Fprintf(os.Stderr, "Email Error: %v\n", err.Error())
		return "Error sending email. Is this a valid email?"
	}
	return ""
}

/*signupHandler: creates an account after validating the validator number
Variables:
	username: username for the account
	email: email for the account
	password: password for the account
	validator: the validation number to be checked
Return: returns a string that is a message to the client*/
func signupHandler(username string, email string, password string, validator int) string {
	re := regexp.MustCompile("^[a-zA-Z0-9]+$")
	if !(re.MatchString(username)) {
		return "Only Alphanumeric Characters"
	}
	if password == "" {
		return "Need a Password"
	}
	var valid string
	err := serverDBs.filesdb.QueryRow("SELECT username FROM validations WHERE username=? AND email=? AND validation=?", username, email, validator).Scan(&valid)
	if err == sql.ErrNoRows {
		return "Validation Fail"
	} else if err != nil {
		return "Validation Query Error"
	}

	hashedPassword := hashAndSalt(password)
	//creates account
	_, err = serverDBs.filesdb.Exec("INSERT INTO accounts(username, email, password, storagetot) VALUES(?, ?, ?, ?)", username, email, hashedPassword, FILE_LIMIT)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error inserting into Accounts: %v\n", err.Error())
		return "Error Setting up Account. Try setting up again."
	}
	//makes directory information
	_, err = serverDBs.filesdb.Exec("INSERT INTO dirs VALUES(?, ?, ?)", username, "/", username)
	if err != nil {
		//if directory information fails, the account won't work so we remove it from accounts to prevent a blank account
		serverDBs.filesdb.Exec("DELETE FROM accounts WHERE username=?", username)
		fmt.Fprintf(os.Stderr, "Error inserting into Dirs: %v\n", err.Error())
		return "Error Setting up Account. Try setting up again."
	}
	return "SUCCESS: You can login now"
}

/*loginCheckHandler: checks if username and password are valid then sends two-step verification email
Variables:
	username: username of account to check
	password: password to account to check
Return: returns a string with a message if failure in check else ""*/
func loginCheckHandler(username string, password string) string {
	var user string
	var hashedPassword string
	var email string
	err := serverDBs.filesdb.QueryRow("Select username, password, email FROM accounts WHERE username=?", username).Scan(&user, &hashedPassword, &email)
	check := checkPassword(hashedPassword, password)
	switch {
	case err == sql.ErrNoRows:
		return "Wrong Username or Password"
	case !check:
		return "Wrong Username or Password"
	case err != nil:
		return "Error looking up Account"
	default:
		//delete any previous attempts to login validation numbers
		_, err = serverDBs.filesdb.Exec("DELETE FROM validations WHERE username=? OR email=?", username, email)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Validation Setup Error: %v\n", err.Error())
			return "Validation Setup Error"
		}
		validator := mrand.Int()
		_, err = serverDBs.filesdb.Exec("INSERT INTO validations(username, email, validation) VALUES(?, ?, ?)", username, email, validator)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Validation Insertion Error: %v\n", err.Error())
			return "Validation Setup Error"
		}
		//send email
		err = serverDBs.send(email, validator, "Login Validation\n")
		if err != nil {
			serverDBs.filesdb.Exec("DELETE FROM validations WHERE username=?", username)
			fmt.Fprintf(os.Stderr, "Email Error: %v\n", err.Error())
			return "Error sending email"
		}
	}
	return ""
}

/*loginHandler: checks username and password again then validation number. Creates a cookie for succesful login. If cookie is sent, checks if it is valid.
Variables:
	username: the account name
	password: password to the account
	cookie: if non-empty, checks if the cookie is valid
	validator: the validation number to check
Return: returns a struct with field Err set on failure and Username and/or Cookie(new valid cookie) fields set on Success*/
func loginHandler(username, password, cookie string, validator int) internal.LoginReturn {
	//check if cookie valid
	if cookie != "" {
		user := serverDBs.is_login(cookie)
		if user != "" {
			return internal.LoginReturn{Username: user}
		} else {
			return internal.LoginReturn{Err: "Login Fail"}
		}
	}

	var user string
	var hashedPassword string
	err := serverDBs.filesdb.QueryRow("Select username, password FROM accounts WHERE username=?", username).Scan(&user, &hashedPassword)
	check := checkPassword(hashedPassword, password)
	fmt.Printf("User: %v\n Err: %v\n", user, err)
	switch {
	case err == sql.ErrNoRows:
		return internal.LoginReturn{Err: "Wrong Username or Password"}
	case !check:
		return internal.LoginReturn{Err: "Wrong Username or Password"}
	case err != nil:
		return internal.LoginReturn{Err: "Fatal"}
	default:
		var valid string
		err := serverDBs.filesdb.QueryRow("SELECT username FROM validations WHERE username=? AND validation=?", username, validator).Scan(&valid)
		if err != nil {
			//Reset validation number so someone can't just keep guessing the same number.
			serverDBs.filesdb.QueryRow("DELETE FROM validations WHERE username=?", username)
			fmt.Fprintf(os.Stderr, "Validation Error: %v\n", err.Error())
			return internal.LoginReturn{Err: "Validation Fail"}
		}
		var cookie string
		//creating cookie for session
		for cookie == "" {
			fmt.Println("Create Cookie...")
			cookie = hex.EncodeToString(createRandId(24))
			var check string
			//make sure there are no duplicate cookies
			err = serverDBs.filesdb.QueryRow("SELECT 1 FROM cookies WHERE cookie=?", cookie).Scan(&check)
			switch {
			case err == sql.ErrNoRows:
			case err != nil:
				return internal.LoginReturn{Err: "Couldn't create Cookie"}
			default:
				cookie = ""
			}
		}

		//Delete previous validations and cookies
		serverDBs.filesdb.Exec("DELETE FROM validations WHERE username=?", user)
		serverDBs.filesdb.Exec("DELETE FROM cookies WHERE username=?", user)
		//the date and time right now
		date := time.Now()
		//add one day to the date and time right now. Makes cookie valid for a day
		expire := date.AddDate(0, 0, 1)
		//right format for sql
		expireString := expire.Format(time.RFC3339)
		serverDBs.filesdb.Exec("INSERT INTO cookies(cookie, username, expire) VALUES(?, ?, ?)", cookie, user, expireString)
		//creates a goroutine to delete the cookie after it expires.
		time.AfterFunc(time.Until(expire), func() { serverDBs.deleteCookie(cookie) })
		//Success
		return internal.LoginReturn{Cookie: cookie, Expire: expireString}
	}
}

// An implementation of a basic server. This implementation
// is absurdly insecure, and is only meant as an example of
// how to implement the methods required by the example client
// provided in client/client.go; it should not be taken as
// a suggestion of how to design your server.

/*uploadHandler: checks that the client is authenticated using the cookie. upload a file from the
users local system to our system in the specfied path. We are checking the access contol of the user
for the path that they input and making sure the client is authenticated.
Variables:
	path: the path for where the user wishes to upload a file
	currDir: The current directory of the user
	bidy: the contents of the file to be uploaded
	cookie: the cookie to be checked
Return: returns a message to the client on whether it succeeded or not.*/
func uploadHandler(path string, currDir string, body []byte, cookie string) string {
	// path = template.HTMLEscapeString(path)
	// currDir = template.HTMLEscapeString(currDir)
	// cookie = template.HTMLEscapeString(cookie)

	username := serverDBs.is_login(cookie)
	if username == "" {
		return "Not Logged In"
	}

	fullPath := makeFullPath(path, currDir)

	i := strings.LastIndex(fullPath, "/")
	superpath := fullPath[0:i]
	filename := fullPath[i+1:]
	// hash body to get file name
	//Could Hash colide causing two different files with same actual filename?
	filehash := sha256.Sum256(body)
	filehashStr := hex.EncodeToString(filehash[:])
	rootuserr := strings.SplitN(fullPath, "/", 3)[1]
	filesize := binary.Size(body)
	fmt.Println(os.Stdout, "this is the size of this file:  ", filesize)

	var rootUserTot int
	err := serverDBs.filesdb.QueryRow(`SELECT storagetot FROM accounts WHERE username=?`, rootuserr).Scan(&rootUserTot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Upload Error: %v\n", err.Error())
		return "Server Error Uploading"
	}
	if rootUserTot-filesize <= 0 {
		return "File limit exceeded for user " + rootuserr
	}

	if isFile(fullPath, username) {
		//check write access
		var rootuser string
		var prevfilehash string
		var write int
		var read int
		err := serverDBs.filesdb.QueryRow(`SELECT rootuser, filehash, write, read FROM 
			files WHERE username=? AND superpath=? AND filename=?`, username, superpath, filename).Scan(&rootuser, &prevfilehash, &write, &read)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Upload Error: %v\n", err.Error())
			return "Server Error Uploading"
		}
		// check if the current user has a write access
		if write == 0 {
			return "Write Access Denied"
		}
		//rehash the thing, and check if it is the same as the previous hash.
		if filehashStr == prevfilehash {
			fmt.Fprintln(os.Stdout, "thisis the point where nothing has changes")
			return ""
		}
		//update filehash of all entries with the same rootuser and filename
		res, err1 := serverDBs.filesdb.Query(`SELECT username,read, write FROM files WHERE rootuser = ? 
			AND superpath=? AND filename = ?`, rootuser, superpath, filename)
		if err1 != nil {
			fmt.Fprintf(os.Stderr, "Upload Error: %v\n", err1.Error())
			return "Server Error Uploading"
		}
		type Item struct {
			thisUser  string
			thisread  int
			thiswrite int
		}
		alist := []Item{}
		for res.Next() {
			var thisUser string
			var thisread int
			var thiswrite int
			fmt.Fprintln(os.Stdout, "this is where the user s"+thisUser)
			if err = res.Scan(&thisUser, &thisread, &thiswrite); err != nil {
				fmt.Fprintf(os.Stderr, "Upload Error: %v\n", err.Error())
				return "Server Error Uploading"
			}
			alist = append(alist, Item{thisUser: thisUser, thisread: thisread, thiswrite: thiswrite})

		}
		for _, i := range alist {

			fmt.Fprintln(os.Stdout, "this /is where the user s")
			_, err = serverDBs.filesdb.Exec(`REPLACE INTO files 
			(username, rootuser, superpath, filehash, filename, read, write) 
			VALUES(?, ?, ?, ?, ?, ?, ?)`, i.thisUser, rootuser, superpath, filehashStr, filename, i.thisread, i.thiswrite)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Upload Error: %v\n", err.Error())
				return "Server Error Uploading"
			}
		}

		//TODO: Change to Actual Current Directory
		err = ioutil.WriteFile(serverDBs.baseDir+"/AllFiles/"+filehashStr, body, 0664)
		err = serverDBs.filesdb.QueryRow(`SELECT * FROM files WHERE filehash=?`, prevfilehash).Scan(nil)
		prevBody, err := ioutil.ReadFile(serverDBs.baseDir + "/AllFiles/" + prevfilehash)
		prevFileSize := binary.Size(prevBody)
		if err == sql.ErrNoRows {
			err = os.Remove(serverDBs.baseDir + "/AllFiles/" + prevfilehash)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Upload Error: %v\n", err.Error())
				return "Server Error Uploading"
			}
			fmt.Fprintln(os.Stdout, "the hash has been deleted since there are no others usin git")
			return ""
		}

		fmt.Fprintln(os.Stdout, "File updated!")
		_, err = serverDBs.filesdb.Exec("UPDATE accounts SET storagetot=? WHERE username=?", rootUserTot-filesize+prevFileSize, rootuser)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Upload Error: %v\n", err.Error())
			return "Server Error Uploading"
		}
		return ""
	}

	if isDir(fullPath) {
		return "A directory already exist with this name"
	}

	fmt.Fprintln(os.Stdout, "File updated!"+username+" "+fullPath)
	actname := strings.SplitN(fullPath, "/", 3)[1]
	if username != actname {
		return "Access Denied"
	}

	if !isDir(superpath) {
		return superpath + "does not exsist. Cannot upload file: " + fullPath
	}

	// write to the file name into Allfiles
	// before writing check it it is in database already
	err = ioutil.WriteFile(serverDBs.baseDir+"/AllFiles/"+filehashStr, body, 0664)
	if err != nil {
		return err.Error()
	}

	_, err = serverDBs.filesdb.Exec("INSERT INTO files VALUES(?, ?, ?, ?, ?, ?, ?)", username, username, superpath, filehashStr, filename, 1, 1)
	if err != nil {
		panic(err)
	}

	_, err = serverDBs.filesdb.Exec("UPDATE accounts SET storagetot=? WHERE username=?", rootUserTot-filesize, rootuserr)
	if err != nil {
		panic(err)
	}

	return ""
}

/*downloadHandler: checks that the client is authenticated using the cookie. download the specfied
file from out remote sytem to the clients local file sytem.
Variables:
	path: the path for the file the user wishes to download
	currDir: The current directory of the user
	cookie: the cookie to be checked
Return: returns a type internal.DownloadReturn that is either the body of the file downloaded or an
error message if it did not succeed.*/
func downloadHandler(path string, currDir string, cookie string) internal.DownloadReturn {
	// path = template.HTMLEscapeString(path)
	// currDir = template.HTMLEscapeString(currDir)
	// cookie = template.HTMLEscapeString(cookie)

	username := serverDBs.is_login(cookie)
	if username == "" {
		return internal.DownloadReturn{Err: "Not Logged in"}
	}

	// get full path
	fullPath := makeFullPath(path, currDir)
	rootuser := strings.SplitN(fullPath, "/", 3)[1]
	//extact super and file name from path and username,
	i := strings.LastIndex(fullPath, "/")
	superpath := fullPath[0:i]
	filename := fullPath[i+1:]

	if !isFile(fullPath, username) {
		return internal.DownloadReturn{Err: "does not exsist. Cannot download file: "}
	}

	// query for super and path and read per
	// check if the user has read permision
	stmt, err := serverDBs.filesdb.Prepare("SELECT filehash,read FROM files WHERE username = ? AND rootuser = ? AND superpath=? AND filename = ?")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Download Error: %v\n", err.Error())
		return internal.DownloadReturn{Err: "Server Error Downloading"}
	}
	// fmt.Fprintln(os.Stdout, "username and superpath: " + username + " " + fullPath)
	res, err := stmt.Query(username, rootuser, superpath, filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Download Error: %v\n", err.Error())
		return internal.DownloadReturn{Err: "Server Error Downloading"}
	}

	var filehash string
	// var ext string
	var read int
	k := 0
	for res.Next() {
		k++
		if err := res.Scan(&filehash, &read); err != nil {
			log.Fatal(err)
		}
		// fmt.Fprintln(os.Stdout, "username and superpath: " + username + " " + fullPath)

	}
	//CHECK THIS LATER WHEN SHARING
	if k == 0 {
		return internal.DownloadReturn{Err: "This file doesnt exist, friend"}
	}
	if read == 0 {
		return internal.DownloadReturn{Err: "You do not have read access to this file anymore, friend"}
	}
	body, err := ioutil.ReadFile(serverDBs.baseDir + "/AllFiles/" + filehash)
	if err != nil {
		return internal.DownloadReturn{Err: err.Error()}
	}
	return internal.DownloadReturn{Body: body}
}

// isDir expects a string fullpath and returns a boolean. If fullpath
// is a path to a directory for a valid directory it outputs true
//else it outputs false. Before calling isDir we have already authenticated the user
// and checked their access control to the directory/fullpath.
func isDir(fullPath string) bool {
	//check if this directory exists
	i := strings.LastIndex(fullPath, "/")
	superpath := fullPath[0:i]
	fmt.Fprintln(os.Stdout, "superpath iss: "+superpath)
	dirName := fullPath[i+1:]
	fmt.Fprintln(os.Stdout, "dirname iss: "+dirName)

	if superpath == "" {
		superpath = "/"
	}

	stmt, err := serverDBs.filesdb.Prepare("SELECT * FROM dirs WHERE superpath = ? AND filename = ?")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Is Error: %v\n", err.Error())
		return false
	}
	res, err := stmt.Query(superpath, dirName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "IsDir Error: %v\n", err.Error())
		return false
	}
	k := 0
	for res.Next() {
		k++
	}
	if k == 0 {
		return false
	}
	return true
}

// isFile expects a string fullpath and a string username. It returns a boolean.
//If fullpath  is a directory that exsist and to which the given usename has access
// the value true is returned, else false is returned.
// Before calling isFile we have already authenticated the user.
func isFile(fullPath string, username string) bool {
	//check if this directory exists
	i := strings.LastIndex(fullPath, "/")
	superpath := fullPath[0:i]
	fmt.Fprintln(os.Stdout, "superpath iss: "+superpath)
	dirName := fullPath[i+1:]
	fmt.Fprintln(os.Stdout, "dirname iss: "+dirName)

	if superpath == "" {
		superpath = "/"
	}

	stmt, err := serverDBs.filesdb.Prepare("SELECT * FROM files WHERE superpath = ? AND filename = ?  AND username = ?")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Is File: %v\n", err.Error())
		return false
	}
	res, err := stmt.Query(superpath, dirName, username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "IsFile Error: %v\n", err.Error())
		return false
	}
	k := 0

	for res.Next() {
		k++
	}
	if k == 0 {
		return false
	}
	return true
}

//The function makeFullPath expects a string path (the users input path) as well as a
// string of the current directory, currDir. It outputs a string. This function check
// whether the path is relative or absolut path and outputs a string representing the fullpath
// accordingly.q
func makeFullPath(path string, currDir string) string {
	fullPath := ""
	if path[0] == '/' {
		fullPath = path
	} else if path == "." {
		fullPath = currDir
	} else {
		fullPath = currDir + "/" + path
	}
	return filepath.Clean(fullPath)
}

// func checkDirAccess(username string, path string) bool {
// 	actname := strings.SplitN(path, "/",3)[1]
// 	if (username != actname){
// 		return  false
// 	}
// 	return true
// }

/*showShareHandler: checks that the client is authenticated using the cookie. Shows who has
shared access and what kind of acess that they have fot a specfied file
Variables:
	path: the path for file the user wishes to view shares of.
	currDir: The current directory of the user
	cookie: the cookie to be checked
Return: returns a type internal.ShareReturn that shows wither the list of share acess or an erro if
it di not succeed to the client.*/
func showShareHandler(path string, currDir string, cookie string) internal.ShareReturn {
	// path = template.HTMLEscapeString(path)
	// currDir = template.HTMLEscapeString(currDir)

	username := serverDBs.is_login(cookie)
	if username == "" {
		return internal.ShareReturn{Err: "Not Logged in"}
	}

	//make full path to file
	fullPath := makeFullPath(path, currDir)
	actname := strings.SplitN(fullPath, "/", 3)[1]
	if username != actname {
		return internal.ShareReturn{Err: "Access Denied!"}
	}

	if !isFile(fullPath, username) {
		return internal.ShareReturn{Err: fullPath + " is not a file"}
	}
	i := strings.LastIndex(fullPath, "/")
	superpath := fullPath[0:i]
	filename := fullPath[i+1:]

	stmt, err := serverDBs.filesdb.Prepare("SELECT username, write FROM files WHERE username!=? AND rootuser=? AND superpath=? AND filename=?")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Show Shares Error: %v\n", err.Error())
		return internal.ShareReturn{Err: "Server Error Showing Shares"}
	}
	res, err := stmt.Query(username, username, superpath, filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Show Shares Error: %v\n", err.Error())
		return internal.ShareReturn{Err: "Server Error Showing Shares"}
	}

	var entries []internal.ShareEnt
	for res.Next() {
		var sharee string
		var write int
		if err := res.Scan(&sharee, &write); err != nil {
			log.Fatal(err)
		}
		w := false
		if write == 1 {
			w = true
		}
		entries = append(entries, internal.ShareEnt{
			Write_: w,
			Name_:  sharee,
		})
	}
	return internal.ShareReturn{Entries: entries}
}

/*listHandler: checks that the client is authenticated using the cookie. lists the content of the
directory for which the user specfied a path.
Variables:
	path: the path the directory the user wishes to remove
	currDir: The current directory of the user
	cookie: the cookie to be checked
Return: returns the internal.Listreturn type containing either a list of the
contents of the directory or any errors encountered to the Client .*/
func listHandler(path string, currDir string, cookie string) internal.ListReturn {
	// path = template.HTMLEscapeString(path)
	// currDir = template.HTMLEscapeString(currDir)
	// cookie = template.HTMLEscapeString(cookie)

	username := serverDBs.is_login(cookie)
	if username == "" {
		return internal.ListReturn{Err: "Not Logged In"}
	}

	//make full path to file
	fullPath := makeFullPath(path, currDir)
	actname := strings.SplitN(fullPath, "/", 3)[1]
	if username != actname {
		return internal.ListReturn{Err: "Access Denied!"}
	}

	if !isDir(fullPath) {
		return internal.ListReturn{Err: fullPath + " does not exsist"}
	}

	//checking dirs
	stmt, err := serverDBs.filesdb.Prepare("SELECT filename FROM dirs WHERE username=? AND superpath=?")
	if err != nil {
		panic(err)
	}
	res, err := stmt.Query(username, fullPath)
	if err != nil {
		panic(err)
	}

	var entries []internal.DirEnt
	for res.Next() {
		var filename string
		if err := res.Scan(&filename); err != nil {
			log.Fatal(err)
		}
		entries = append(entries, internal.DirEnt{
			IsDir_: true,
			Name_:  filename,
		})
	}

	//checking files
	stmt2, err := serverDBs.filesdb.Prepare("SELECT filename FROM files WHERE username=? AND superpath=?")
	if err != nil {
		panic(err)
	}
	res2, err := stmt2.Query(username, fullPath)
	if err != nil {
		panic(err)
	}

	for res2.Next() {
		var filename string
		if err := res2.Scan(&filename); err != nil {
			log.Fatal(err)
		}
		entries = append(entries, internal.DirEnt{
			IsDir_: false,
			Name_:  filename,
		})
	}

	return internal.ListReturn{Entries: entries}
}

//The function mkdirHandler expects a string path (the path the user inputs), a string,
//the current directory the user is at and a sting representing the users cookie. It
//outputs a string. The function checks to make sure that a user is valid and has been
//authenticated. It then checks to make sure that a user has access to make a directory
//in the path that they specified if it doesn't it returns an appropriate string
//detailing the error. However if it does it goes on to check that such a directory does not
//exsist and if it doesn't it makes the directory with the given name. If successful it retuns
//an empty string, else it returns a string detailing the error.

/*mkdirHandler: checks that the client is authenticated using the cookie. Makes a directory at the
specified path, if a directory or file does not exsist with that name in the given loaction.
Variables:
	path: the path where the user wishes to make a directory
	currDir: The current directory of the user
	cookie: the cookie to be checked
Return: returns a message to the client on whether it succeeded or not.*/
func mkdirHandler(path string, currDir string, cookie string) string {
	// path = template.HTMLEscapeString(path)
	// currDir = template.HTMLEscapeString(currDir)
	// cookie = template.HTMLEscapeString(cookie)

	username := serverDBs.is_login(cookie)
	if username == "" {
		return "Not Logged In"
	}

	//make full path to file
	fullPath := makeFullPath(path, currDir)
	actname := strings.SplitN(fullPath, "/", 3)[1]
	if username != actname {
		return "\nAccess Denied!"
	}

	if isDir(fullPath) {
		return "\nA file with the name already exist!"
	}

	i := strings.LastIndex(fullPath, "/")
	superpath := fullPath[0:i]
	dirName := fullPath[i+1:]

	if !isDir(superpath) {
		return superpath + "does not exsist. Cannot create directory: " + dirName
	}

	stmt, err := serverDBs.filesdb.Prepare("INSERT INTO dirs VALUES(?, ?, ?)")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Mkdir Error: %v\n", err.Error())
		return "Server Error Making Dir"
	}

	_, err = stmt.Exec(username, superpath, dirName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Mkdir Error: %v\n", err.Error())
		return "Server Error Making Dir"
	}

	return ""
}

//The Fuction remDir is a recursive fuction and is called in removeHandler.
//It expects a string username, the username of the user, a string supepath, which is
//the file path to the directory or file to be removed and a string dirName, the name
//of the directory. It return to the user a String. remDir works by recurisively deleting
// the contents of the directory. It removes the information from the database as well as
//from the AllFiles folder. It also checks for files that are deduplicates before deleting a file.
//for a director it will remove that directory and it's subcontents including other files and
//directories withing that directory and withing the subcontents of that directory. For a file
//it will simply remove that file. If successful it returns an empty string, else it returns a
// string detailing the error that occured. Before this function is called we have already
//authenticated users and checked for acess control.
func remDir(username string, superpath string, dirName string) string {
	var fname string
	var children []string
	fullPath := superpath + "/" + dirName

	if isFile(fullPath, username) {

		stmt, err1 := serverDBs.filesdb.Prepare("SELECT filehash FROM files WHERE rootuser = ? AND superpath = ? AND filename = ?")
		if err1 != nil {
			panic(err1)
		}

		res, err2 := stmt.Query(username, superpath, dirName)
		if err2 != nil {
			panic(err2)
		}

		var filehash string
		for res.Next() {
			if err := res.Scan(&filehash); err != nil {
				log.Fatal(err)
			}
		}

		stmt, err := serverDBs.filesdb.Prepare("DELETE FROM files WHERE rootuser = ? AND superpath = ? AND filename = ?")
		if err != nil {
			panic(err)
		}

		_, err = stmt.Exec(username, superpath, dirName)
		if err != nil {
			panic(err)
		}

		fmt.Fprintln(os.Stdout, filehash)

		stmt, err1 = serverDBs.filesdb.Prepare("SELECT username FROM files WHERE filehash = ?")
		if err1 != nil {
			panic(err1)
		}

		ress, err3 := stmt.Query(filehash)
		if err3 != nil {
			panic(err2)
		}

		k := 0

		for ress.Next() {
			k++
		}

		var rootUserTot int
		err = serverDBs.filesdb.QueryRow(`SELECT storagetot FROM accounts WHERE username=?`, username).Scan(&rootUserTot)
		if err != nil {
			panic(err)
		}

		initBody, err := ioutil.ReadFile(serverDBs.baseDir + "/AllFiles/" + filehash)
		prevFileSize := binary.Size(initBody)

		if k == 0 {
			os.Remove(serverDBs.baseDir + "/AllFiles/" + filehash)
		}
		_, err = serverDBs.filesdb.Exec("UPDATE accounts SET storagetot=? WHERE username=?", rootUserTot+prevFileSize, username)
		if err != nil {
			panic(err)
		}

		//remove file from allFiles folder in this case
		return ""
	}

	// removing the files within this directory
	stmt, err := serverDBs.filesdb.Prepare("SELECT filename FROM files WHERE rootuser = ? AND superpath = ?")
	if err != nil {
		panic(err)
	}

	res, errs := stmt.Query(username, fullPath)
	if errs != nil {
		panic(err)
	}

	for res.Next() {
		err := res.Scan(&fname)
		if err != nil {
			log.Fatal(err)
		}

		children = append(children, fname)
	}

	//removing directorys within this dirctory
	stmt, err = serverDBs.filesdb.Prepare("SELECT filename FROM dirs WHERE username = ? AND superpath = ?")
	if err != nil {
		panic(err)
	}

	res, err = stmt.Query(username, fullPath)
	if err != nil {
		panic(err)
	}

	for res.Next() {
		err := res.Scan(&fname)
		if err != nil {
			log.Fatal(err)
		}
		children = append(children, fname)
	}

	for i, v := range children {
		i = i
		remDir(username, fullPath, v)
	}

	stmt, err = serverDBs.filesdb.Prepare("DELETE FROM dirs WHERE username = ? AND superpath = ? AND filename = ?")
	if err != nil {
		panic(err)
	}

	_, err = stmt.Exec(username, superpath, dirName)
	if err != nil {
		panic(err)
	}

	return ""
}

//removeHandler expects a string path, the path for the file or directory that the user wishes
//to remove, a string currDir, the current directory within which the user is working, a boolean dir,
// indicating whether the user wanted to recursively delete a directory, and a cookie. The
//works by first checking to make sure that the user has been authenticated. We then check to make
// sure that the user has access to the directory or file that they wished to delete. We then check
//whether the path the user gives is to a valid path or directory. If it for a valid path and the
//dir boolean is false we don't continue. However if the dir value is ture and the path is for a
//valid dir we recursively delte the contents of that directory using our helper function remDir.
//If the path is actually for a valid file we just delete that file also using the same
//helper function. If successful it returns an empty string, else it returns a
// string detailing the error that occured.

/*removeHandler: checks that the client is authenticated using the cookie. removes the sepecfied path
or directory if it exsist and is dir is correctly specified
Variables:
	path: the path for file or directory the user wishes to remove
	currDir: The current directory of the user
	dir: bool spefying whether to remove directory or not
	cookie: the cookie to be checked
Return: returns a message to the client on whether it succeeded or not.*/
func removeHandler(path string, currDir string, dir bool, cookie string) string {
	// path = template.HTMLEscapeString(path)
	// currDir = template.HTMLEscapeString(currDir)
	// cookie = template.HTMLEscapeString(cookie)

	username := serverDBs.is_login(cookie)
	if username == "" {
		return "Not Logged In"
	}

	//make full path to file
	fullPath := makeFullPath(path, currDir)
	actname := strings.SplitN(fullPath, "/", 3)[1]
	if username != actname {
		return "Access Denied! You can only share a file that is yours"
	}

	i := strings.LastIndex(fullPath, "/")
	superpath := fullPath[0:i]
	dirName := fullPath[i+1:]

	isdir := isDir(fullPath)
	isfile := isFile(fullPath, username)

	if isdir && !dir {
		return "rm: " + dirName + ": is a directory. Use -r to remove a directory"
	} else if !isdir && !isfile {
		return "rm: " + dirName + ": no such file or directory found"
	}

	err := remDir(username, superpath, dirName)

	return err
}

/*cdHandler: checks that the client is authenticated using the cookie. changes the
directory of the user
Variables:
	path: the path for file for which the user wishes to change their directory to
	currDir: The current directory of the user
	cookie: the cookie to be checked
Return: returns a message to the client on whether it succeeded or not.*/
func cdHandler(path string, currDir string, cookie string) internal.PWDReturn {
	// path = template.HTMLEscapeString(path)
	// currDir = template.HTMLEscapeString(currDir)
	// cookie = template.HTMLEscapeString(cookie)

	username := serverDBs.is_login(cookie)
	if username == "" {
		return internal.PWDReturn{Err: "Not Logged In"}
	}
	//make full path to file
	fullPath := makeFullPath(path, currDir)
	actname := strings.SplitN(fullPath, "/", 3)[1]
	if username != actname {
		return internal.PWDReturn{Err: fullPath + "Access Denied"}
	}

	if isDir(fullPath) {
		return internal.PWDReturn{Path: fullPath}
	}
	return internal.PWDReturn{Err: fullPath + "Directory does not exist"}
}

/*shareHandler: checks that the client is authenticated using the cookie. Adds
shares for a given file for a particular user
Variables:
	path: the path for file for which share is to be added
	currDir: The current directory of the user
	otherUser: The user with which the client wish to add the share for the file
	write: a bool determining wheteher the user should have write access
	cookie: the cookie to be checked
Return: returns a message to the client on whether it succeeded or not.*/
func shareHandler(path string, currDir string, otherUser string, write bool, cookie string) string {
	// path = template.HTMLEscapeString(path)
	// currDir = template.HTMLEscapeString(currDir)
	// otherUser = template.HTMLEscapeString(otherUser)
	// cookie = template.HTMLEscapeString(cookie)

	username := serverDBs.is_login(cookie)
	if username == "" {
		return "Not Logged In"
	}

	//make full path to file
	fullPath := makeFullPath(path, currDir)
	actname := strings.SplitN(fullPath, "/", 3)[1]
	if username != actname {
		return "Access Denied! You can only share a file that is yours"
	}
	//MAKE SURE USER EXISTS
	err := serverDBs.filesdb.QueryRow("SELECT * FROM accounts WHERE username=?", otherUser).Scan(nil)
	if err == sql.ErrNoRows {
		return "User " + otherUser + "does not exist"
	}

	if isDir(fullPath) {
		return "Cannot share. Path is a directory"
	}
	if !isFile(fullPath, username) {
		return "File does not exist"
	}
	i := strings.LastIndex(fullPath, "/")
	superpath := fullPath[0:i]
	filename := fullPath[i+1:]
	// ext := filepath.Ext(path)

	// get filehash of file
	stmt, err := serverDBs.filesdb.Prepare("SELECT filehash FROM files WHERE username = ? AND superpath=? AND filename = ?")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sharefiles Error: %v\n", err.Error())
		return "Server Error sharing file"
	}

	res, err1 := stmt.Query(username, superpath, filename)
	if err1 != nil {
		fmt.Fprintf(os.Stderr, "Sharefiles Error: %v\n", err1.Error())
		return "Server Error sharing file"
	}

	var filehashStr string
	for res.Next() {
		if err := res.Scan(&filehashStr); err != nil {
			log.Fatal(err)
		}
	}
	w := 0
	if write {
		w = 1
	}

	stmt, err2 := serverDBs.filesdb.Prepare(`REPLACE INTO files 
											(username, rootuser, superpath, filehash, filename, read, write)
											 VALUES(?, ?, ?, ?, ?, ?, ?)`)
	if err2 != nil {
		fmt.Fprintf(os.Stderr, "Sharefiles Error: %v\n", err2.Error())
		return "Server Error sharing file"
	}
	_, err = stmt.Exec(otherUser, username, superpath, filehashStr, filename, 1, w)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sharefiles Error: %v\n", err.Error())
		return "Server Error sharing file"
	}

	return ""
}

/*rmShareHandler: checks that the client is authenticated using the cookie. removes thes
shares for a given file for a particular user
Variables:
	path: the path for file for which share is to be removed
	cookie: the cookie to be checked
	currDir: The current directory of the user
	otherUser: The user with which the client wish to remove the share for the file
Return: returns a message to the client on whether it succeeded or not.*/
func rmShareHandler(path string, currDir string, otherUser string, cookie string) string {
	// path = template.HTMLEscapeString(path)
	// currDir = template.HTMLEscapeString(currDir)
	// otherUser = template.HTMLEscapeString(otherUser)
	// cookie = template.HTMLEscapeString(cookie)

	username := serverDBs.is_login(cookie)
	if username == "" {
		return "Not Logged In"
	}

	//make full path to file
	fullPath := makeFullPath(path, currDir)
	actname := strings.SplitN(fullPath, "/", 3)[1]
	if username != actname {
		return "Access Denied! You can only remove share of a file that is yours"
	}
	if isDir(fullPath) {
		return "Cannot remove share. Path is a directory"
	}
	if !isFile(fullPath, username) {
		return "File does not exist"
	}
	i := strings.LastIndex(fullPath, "/")
	superpath := fullPath[0:i]
	filename := fullPath[i+1:]
	//ext := filepath.Ext(path)

	// get filehash of file
	stmt, err := serverDBs.filesdb.Prepare("SELECT filehash FROM files WHERE username = ? AND superpath=? AND filename = ?")
	if err != nil {
		fmt.Fprintf(os.Stderr, "rm Sharefiles Error: %v\n", err.Error())
		return "Server Error removing share file"
	}
	// fmt.Fprintln(os.Stdout, "username and superpath: " + username + " " + fullPath)
	res, err1 := stmt.Query(username, superpath, filename)
	if err1 != nil {
		fmt.Fprintf(os.Stderr, "rm Sharefiles Error: %v\n", err1.Error())
		return "Server Error removing share file"
	}

	var filehashStr string
	for res.Next() {
		if err := res.Scan(&filehashStr); err != nil {
			log.Fatal(err)
		}
	}

	stmt, err2 := serverDBs.filesdb.Prepare("DELETE FROM files WHERE rootuser = ? AND username = ? AND superpath = ? AND filehash = ? ")
	if err2 != nil {
		fmt.Fprintf(os.Stderr, "rm Sharefiles Error: %v\n", err2.Error())
		return "Server Error removing share file"
	}
	fmt.Fprintln(os.Stdout, "balalalala")
	_, err = stmt.Exec(username, otherUser, superpath, filehashStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rm Sharefiles Error: %v\n", err.Error())
		return "Server Error removing share file"
	}
	return ""
	// add an entry to databse that with read as one and check if write is true or false
}

/*logoutHandler: invalidates a cookie to end a session
Variables:
	cookie: the cookie to be invalidated
Return: returns a message to the client of success or failure*/
func logoutHandler(cookie string) string {
	user := serverDBs.is_login(cookie)
	if user == "" {
		return "Not Logged In"
	}
	serverDBs.deleteCookie(cookie)
	return "Logged Out"
}

/*delCheckHandler: checks that a cookie is valid then sends a validation email
Variable:
	cookie: the cookie to be checked
Return: returns a message to the client on Error or "" on Success*/
func delCheckHandler(cookie string) string {
	// cookie = template.HTMLEscapeString(cookie)
	user := serverDBs.is_login(cookie)
	if user == "" {
		return "Not Logged In"
	}
	var email string
	err := serverDBs.filesdb.QueryRow("SELECT email FROM accounts WHERE username=?", user).Scan(&email)
	if err != nil {
		return "Problem finding email"
	}
	//get rid of previous validation attempts
	_, err = serverDBs.filesdb.Exec("DELETE FROM validations WHERE username=? OR email=?", user, email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Validation Setup Error: %v\n", err.Error())
		return "Validation Setup Error"
	}
	validator := mrand.Int()
	_, err = serverDBs.filesdb.Exec("INSERT INTO validations(username, email, validation) VALUES(?, ?, ?)", user, email, validator)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Validation Insertion Error: %v\n", err.Error())
		return "Validation Setup Error"
	}
	err = serverDBs.send(email, validator, "ACCOUNT DELETION VALIDATION\nSomeone has requested an ACCOUNT DELETION for your account.\n")
	if err != nil {
		//get rid of bad validation number after email fail
		serverDBs.filesdb.Exec("DELETE FROM validations WHERE username=?", user)
		fmt.Fprintf(os.Stderr, "Email Error: %v\n", err.Error())
		return "Error sending validation email"
	}
	return ""
}

/*delAccountHandler: checks the cookie with the password then the validation number. After all checks out, it deletes the account
Variables:
	cookie: the cookie to be checked
	password: the password to be checked with the cookie
	validator: the validation number to be checked
Return: returns a message to the client on whether it succeeded or not.*/
func delAccountHandler(cookie string, password string, validator int) string {
	// password = template.HTMLEscapeString(password)
	// cookie = template.HTMLEscapeString(cookie)

	user := serverDBs.is_login(cookie)
	if user == "" {
		return "Not Logged In"
	}
	var hashedPassword string
	var email string
	err := serverDBs.filesdb.QueryRow("Select password, email FROM accounts WHERE username=?", user).Scan(&hashedPassword, &email)
	check := checkPassword(hashedPassword, password)
	switch {
	case err == sql.ErrNoRows:
		return "Wrong Username or Password"
	case !check:
		return "Wrong Username or Password"
	case err != nil:
		return "Query Error"
	default:
		var valid string
		err := serverDBs.filesdb.QueryRow("SELECT username FROM validations WHERE username=? AND email=? AND validation=?", user, email, validator).Scan(&valid)
		if err != nil {
			return "Validation Fail"
		}
		//SUCCESSFUL DELETION
		//DELETE MORE: FILES, DIRECTORY, SHARING, ...

		serverDBs.filesdb.Exec("DELETE FROM accounts WHERE username=?", user)
		serverDBs.filesdb.Exec("DELETE FROM validatons WHERE username=?", user)
		serverDBs.filesdb.Exec("DELETE FROM cookies WHERE username=?", user)
		serverDBs.filesdb.Exec("DELETE FROM files WHERE username=?", user)
		remDir(user, "/", user)
		remDir(user, "", user)

		// serverDBs.filesdb.Exec("DELETE FROM files WHERE rootuser=?", user)
		// serverDBs.filesdb.Exec("DELETE FROM dirs WHERE username=?", user)

		return "SUCCESSFUL DELETION"
	}
}

func finalizer() {
	serverDBs.filesdb.Close()
	fmt.Println("Shutting down...")
}
