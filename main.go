package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"text/template"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
)

var (
	port = 8000

	dbName = "postgres"
	dbUser = "myuser"
	dbPass = "mypass"

	enableConsole = true   // Enable or disable console logging
	enableFile    = true   // Enable or disable file logging
	logFile       *os.File // File to write logs

	templates = template.Must(template.ParseFiles("templates/login.html", "templates/signup.html"))
	store     = sessions.NewCookieStore([]byte("your-secret-key"))
)

var db *sql.DB // Define db variable at package level

func main() {
	var err error

	if enableFile {
		logFile, err = os.Create("server.log")
		if err != nil {
			log.Fatal("Error creating log file:", err)
		}
		defer logFile.Close()
	}

	// Create a multi-writer to log to both the console and the file
	var multiWriter io.Writer
	if enableConsole && enableFile {
		multiWriter = io.MultiWriter(os.Stdout, logFile)
	} else if enableConsole {
		multiWriter = os.Stdout
	} else if enableFile {
		multiWriter = logFile
	} else {
		multiWriter = io.Discard // No logging
	}

	log.SetOutput(multiWriter)
	log.SetFlags(log.Ldate | log.Ltime) // Customize log format if needed

	// Update the database connection to use PostgreSQL
	connStr := "user=" + dbUser + " password=" + dbPass + " dbname=" + dbName + " sslmode=disable"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Error opening database:", err)
		return
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			log.Println("Error closing database:", cerr)
		}
	}()

	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    `)
	if err != nil {
		log.Fatal("Error creating users table:", err)
		return
	}

	r := mux.NewRouter()

	r.HandleFunc("/", indexHandler).Methods("GET")
	r.HandleFunc("/signup", signupHandler).Methods("GET")
	r.HandleFunc("/signup", createUserHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/dashboard", dashboardHandler).Methods("GET")
	r.HandleFunc("/admin", adminHandler).Methods("GET")
	r.HandleFunc("/logout", logoutHandler).Methods("GET")

	http.Handle("/", r)

	log.Println("Server started at :" + fmt.Sprint(port))
	http.ListenAndServe(":"+fmt.Sprint(port), nil)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "login.html", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// In a real application, you would compare the provided credentials with stored user data.
	// For this example, we'll just use some hardcoded values.
	if username == "user" && password == "password" {
		fmt.Println("Successful login for user:", username) // Log the successful login
		session, _ := store.Get(r, "session")
		session.Values["username"] = username
		session.Save(r, w)
		http.Redirect(w, r, "/admin", http.StatusSeeOther) // Redirect to the admin page
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	username, ok := session.Values["username"].(string)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	data := struct {
		Username string
	}{
		Username: username,
	}

	templates.ExecuteTemplate(w, "dashboard.html", data)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	delete(session.Values, "username")
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	username, ok := session.Values["username"].(string)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	data := struct {
		Username string
	}{
		Username: username,
	}

	templates.ExecuteTemplate(w, "admin.html", data)
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Entering signupHandler")
	err := templates.ExecuteTemplate(w, "signup.html", nil)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		fmt.Println("Error executing template:", err)
		return
	}
	fmt.Println("Exiting signupHandler")
}

func createUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Hash the password using a proper hashing library like bcrypt
	hashedPassword, err := hashPassword(password)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		log.Println("Error hashing password:", err)
		return
	}

	// Insert user data into the database
	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, hashedPassword)
	if err != nil {
		log.Println("Error creating user:", err)
		http.Redirect(w, r, "/signup", http.StatusSeeOther)
		return
	}

	log.Println("User created:", username)
	http.Redirect(w, r, "/", http.StatusSeeOther) // Redirect to login page
}

func hashPassword(password string) (string, error) {
	// In a real application, use a proper password hashing library (e.g., bcrypt)
	// This is a simple example for demonstration purposes only
	return password, nil
}
