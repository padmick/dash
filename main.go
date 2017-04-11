package main

import (
	//need to type 'go get database/sql' into cmder to use
	"database/sql" // This allows us to use the SQL Database
	"encoding/json"
	"html/template"
	"log"
	"time"
	//Use json

	"net/http" // http allows HTTP client & server use/implementations
	"os"       //standard input output
	//"github.com/gorilla/mux"
	//"github.com/golang/crypto/bcrypt"
	"github.com/gorilla/securecookie" //Using gorilla to handle cookies
	//need to type ' go get github.com/go-sql-driver/mysql' into cmder to use
	_ "github.com/go-sql-driver/mysql" // This installs a driver in order to be able to use mySQL
	//need to type 'go get golang.org/x/crypto/bcrypt' into cmder to use

	//_ "github.com/mattn/go-sqlite3" //sqlite3 driver
	"golang.org/x/crypto/bcrypt"    // This import statement allows encryption and decryption of passwords
)

//A variable which initialises the use of mysql
var db *sql.DB

// A variable to handle errors
var err error

// cookies are handled here

var cookieHandler = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32))

//Reading cookies for username
func getUserName(request *http.Request) (userName string) {
	if cookie, err := request.Cookie("session"); err == nil {
		cookieValue := make(map[string]string)
		if err = cookieHandler.Decode("session", cookie.Value, &cookieValue); err == nil {
			userName = cookieValue["username"]
		}
	}
	return userName
}

//Saves username in map then encodes with value map and stores that in a cookie
func setSession(userName string, response http.ResponseWriter) {
	value := map[string]string{
		"username": userName,
	}
	if encoded, err := cookieHandler.Encode("session", value); err == nil {
		cookie := &http.Cookie{
			Name:  "session",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(response, cookie)
	}
}

//Returns to indexPage and clears cookies
func clearSession(response http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(response, cookie)
}

//We start off with a Signup function so the user can Signup
// We initialise the use of the response (res) using the ResponseWriter
// and the request (req) by using http.Request
func signupPage(res http.ResponseWriter, req *http.Request) {
	//If the request is not a POST method (the POST request method requests that a web server accept and store
	// the data enclosed in the body of the request message. It is used when submitting a completed web Form)
	if req.Method != "POST" {
		//then serve the SignUp page
		http.ServeFile(res, req, "Signup.html")
		return
	}

	//The username and password are set up as a formValue
	username := req.FormValue("username")
	password := req.FormValue("password")

	//the user is initialised as a string
	var user string

	// Query the database to see if the user signing in is clashing credentials
	//with any existing users within the database
	err := db.QueryRow("SELECT username FROM users WHERE username=?", username).Scan(&user)

	//a switch statement to handle the signin
	switch {
	case err == sql.ErrNoRows:
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		//If the error list is not equal to null, in other words if there is (are) error(s)
		if err != nil {
			//There will be a server error 500 and your account will not be created
			http.Error(res, "Server error, unable to create your account.", 500)
			return
		}

		// The "_" (blank identifier) avoids having to declare all the variables for the return values.
		// Try inserting a username and password into the users table and encrypt the password
		_, err = db.Exec("INSERT INTO users(username, password) VALUES(?, ?)", username, hashedPassword)
		//If there are errors
		if err != nil {
			// The response (res) will say Server error 500 and you can't create your account
			http.Error(res, "Server error, unable to create your account.", 500)
			return
		}

		// Otherwise A user is created
		res.Write([]byte("User created!"))
		return
		//checking for additional server errors(server not available, table deleated etc)
	case err != nil:
		http.Error(res, "Server error, unable to create your account.", 500)
		return
		// by default the root page (/Index.html) is shown to the user
		// error 301 checks if the page has been moved permanantly
	default:
		http.Redirect(res, req, "/", 301)
	}
}

// This is a function to allow a user to log into the website
func loginPage(res http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.ServeFile(res, req, "Login.html")
		return
	}

	username := req.FormValue("username")
	password := req.FormValue("password")

	//This time we have a Username variable and a Password variable
	var databaseUsername string
	var databasePassword string

	//Scan the database to find the returning user as they login with their username and password
	err := db.QueryRow("SELECT username, password FROM users WHERE username=?", username).Scan(&databaseUsername, &databasePassword)
	db.SetMaxIdleConns(0)
	db.SetMaxOpenConns(2)
	//If there are errors with the user logging in
	if err != nil {
		//Error 301 (page moved permanantly)
		http.Redirect(res, req, "/Login.html", 301)
		return
	}
	//comparing the password the user is entering with the encrypted one in the database
	err = bcrypt.CompareHashAndPassword([]byte(databasePassword), []byte(password))
	//If there are no errors then it redirects to the login page, otherwise if the page has been moved - 301 error
	if err != nil {
		http.Redirect(res, req, "/Login.html", 301)
		return
	}

	//If all is successful, serve up the internal.html file which only a logged-in user should be able to see
	http.ServeFile(res, req, "Internal.html")
	//res.Write([]byte("Hello" + databaseUsername))
}

//A function to serve up the homepage called index.html which includes the login and signup buttons
func homePage(res http.ResponseWriter, req *http.Request) {
	http.ServeFile(res, req, "Index.html")
}

/* func scoresPage(res http.ResponseWriter, req *http.Request) {

	http.ServeFile(res, req, "Scores.html")
} */

var scoresPageString = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title></title>
</head>
<body>
	<ul>
	{{range .}}
		<li>	
			<span>{{.Score}}</span>
		</li>
	{{end}}
	</ul>
</body>
</html>`

type score struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	Version   string    `json:"version"`
	Deleted   bool      `json:"deleted"`
	Text      string    `json:"text"`
	Complete  bool      `json:"complete"`
	Score     string    `json:"score"`
}

// Create a template by parsing your html file(s), no need to call this everytime insite the scoresPage function.
var scoresTemplate = template.Must(template.New("scores").Parse(scoresPageString))

func scoresPage(res http.ResponseWriter, req *http.Request) {
	//Connecting to SwaggerUI API to get Scores from Azure for UWP Application
	req, err := http.NewRequest("GET", os.ExpandEnv("https://brainworksappservice.azurewebsites.net/tables/TodoItem?$select=score"), nil)
	if err != nil {
		log.Fatal(err)
	}

	//You have to specify these headers
	req.Header.Set("Accept", "application/json")
	//If you do not specify what version your API is, you cannot receive the JSON
	req.Header.Set("Zumo-Api-Version", "2.0.0")

	//Do the request
	resp, err := http.DefaultClient.Do(req)
	//Error if the request cannot be done
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close() //You need to close the Body everytime, as if you don't you could leak information

	// initialize scores to be passed to the json decoder.
	scores := []*score{}

	// use json.NewDecoder to decode the whole body right into the socres value.
	if err := json.NewDecoder(resp.Body).Decode(&scores); err != nil {
		log.Fatal(err)
	}

	// render the scores
	if err := scoresTemplate.Execute(res, scores); err != nil {
		log.Fatal(err)
	}
}

//Main function
func main() {
	//Open an sql connection, and handle errors,
	// The database is mysql, then we have the username of the server on Azure (b71da173aea4cf)
	// (05606ea1)
	//TCP stands for Transmission Control Protocol which is a set of networking protocols that allows
	// two or more computers to communicate
	// (eu-cdbr-azure-west-a.cloudapp.net)
	// Port Name on Azure (3306)
	// The name of the database (godatabase)
	db, err = sql.Open("mysql", "b7dbd266335e2d:f8c37e44@tcp(eu-cdbr-azure-north-e.cloudapp.net:3306)/acsm_216f071e50500f5")
	//db, err = sql.Open("mysql", "b332s11064b4ce:0def6409@tcp(us-cdbr-azure-southcentral-f.cloudapp.net:3306)/db4go")
	//If there are errors connecting to the server
	if err != nil {
		//output a panic error
		panic(err.Error())
	}
	//close the connection to the database
	defer db.Close()

	//Checking is the connection to the database still alive
	err = db.Ping()
	//otherwise painic
	if err != nil {
		panic(err.Error())
	}

	//Connecting to SwaggerUI API to get Scores from Azure for UWP Application

	/*req, err := http.NewRequest("GET", os.ExpandEnv("https://brainworksappservice.azurewebsites.net/tables/TodoItem?$select=score"), nil)
	if err != nil {
		log.Fatal(err)
	}
	//You have to specify these headers
	req.Header.Set("Accept", "application/json")
	//If you do not specify what version your API is, you cannot receive the JSON
	req.Header.Set("Zumo-Api-Version", "2.0.0")

	type Score struct {
		ID        string    `json:"ID"`
		CreatedAt time.Time `json:"createdAt"`
		UpdatedAt time.Time `json:"updatedAt"`
		Version   string    `json:"version"`
		Deleted   bool      `json:"deleted"`
		Text      string    `json:"text"`
		Complete  bool      `json:"complete"`
		Score     string    `json:"score"`
	}

	scores := []*Score{{
		ID:        "123",
		CreatedAt: time.Now(),
		Version:   "2.0.0",
		Deleted:   false,
		Score:     "185",
	}, {

		ID:        "44442",
		CreatedAt: time.Now(),
		Version:   "2.0.0",
		Deleted:   true,
		Score:     "97",
	}}

	//Do the request
	resp, err := http.DefaultClient.Do(req)
	//Error if the request cannot be done
	if err != nil {
		log.Fatal(err)
	}

	//You need to close the Body everytime, as if you don't you could leak information
	defer resp.Body.Close()

	//Read all of the information from the body
	body, err := ioutil.ReadAll(resp.Body)

	//Error if the info cannot be read
	if err != nil {
		log.Fatal(err)
	}

	tmp, err := template.New("scores").Parse(scoresPages)
	if err != nil {
		panic(err)
	}
	tmp.Execute(res, scores)

	//Write the JSON to the standard output (the Console)
	_, err = os.Stdout.Write(body)
	//Error if the info cannot be output to the console
	if err != nil {
		log.Fatal(err)
	}*/

	//Handle all of our functions
	http.HandleFunc("/Signup.html", signupPage)
	http.HandleFunc("/Login.html", loginPage)
	http.HandleFunc("/", homePage)
	http.HandleFunc("/scores", scoresPage)

	//serve on the port 8000 forever
	http.ListenAndServe(":8000", nil)
}