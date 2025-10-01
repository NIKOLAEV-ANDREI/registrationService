// main.go
package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/go-sql-driver/mysql"
)

type User struct {
	ID       int
	Username string
	Role     string
}

var (
	db       *sql.DB
	store    *sessions.CookieStore
	templates map[string]*template.Template
)

//компилирует HTML шаблоны
func initTemplates() {
	templates = make(map[string]*template.Template)
	templates["register"] = template.Must(template.ParseFiles("templates/register.html"))
	templates["login"] = template.Must(template.ParseFiles("templates/login.html"))
	templates["user"] = template.Must(template.ParseFiles("templates/user.html"))
	templates["admin"] = template.Must(template.ParseFiles("templates/admin.html"))
}

//подключается к MySQL базе данных
func connectDB() *sql.DB {
	// По умолчанию: пользователь 'root', без пароля, база 'user_admin_service'
	dsn := "root:@tcp(127.0.0.1:3306)/user_admin_service?charset=utf8mb4&parseTime=True&loc=Local"
	
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Ошибка подключения к базе данных:", err)
	}
	
	if err := db.Ping(); err != nil {
		log.Fatal("Ошибка проверки подключения к базе данных:", err)
	}
	
	log.Println("Успешное подключение к базе данных")
	return db
}

//создает первого администратора, если он не существует
func createFirstAdmin() {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'admin'").Scan(&count)
	if err != nil {
		log.Fatal("Ошибка проверки существования админа:", err)
	}
	
	if count == 0 {
		// Хэш пароль
		passwordHash, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal("Ошибка хэширования пароля админа:", err)
		}
		
		_, err = db.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
			"admin", string(passwordHash), "admin")
		if err != nil {
			log.Fatal("Ошибка создания первого админа:", err)
		}
		log.Println("Создан первый администратор: логин='admin', пароль='admin123'")
	}
}

//валидность логина
func validateUsername(username string) bool {
	if len(username) < 5 {
		return false
	}
	matched, _ := regexp.MatchString("^[a-zA-Z0-9_-]+$", username)
	return matched
}

//валидность пароля
func validatePassword(password string) bool {
	return len(password) >= 8
}

//получает пользователя по логину
func getUserByUsername(username string) (*User, error) {
	user := &User{}
	err := db.QueryRow("SELECT id, username, role FROM users WHERE username = ?", username).Scan(
		&user.ID, &user.Username, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return user, nil
}

//создает нового пользователя
func createUser(username, password, role string) error {
	//существует ли уже такой логин
	existingUser, err := getUserByUsername(username)
	if err != nil {
		return err
	}
	if existingUser != nil {
		return fmt.Errorf("пользователь с таким логином уже существует")
	}
	
	//Хэш пароль
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	
	_, err = db.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
		username, string(passwordHash), role)
	return err
}

//проверяет учетные данные пользователя
func authenticate(username, password string) (*User, error) {
	var passwordHash string
	var user User
	
	err := db.QueryRow("SELECT id, username, role, password_hash FROM users WHERE username = ?", username).Scan(
		&user.ID, &user.Username, &user.Role, &passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("неверный логин или пароль")
		}
		return nil, err
	}
	
	// Проверяем пароль
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("неверный логин или пароль")
	}
	
	return &user, nil
}

//случайный ключ для сессии
func generateSessionKey() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

//получает пользователя из сессии
func getUserFromSession(r *http.Request) (*User, error) {
	session, _ := store.Get(r, "user-session")
	userID, ok := session.Values["user_id"].(int)
	if !ok {
		return nil, fmt.Errorf("пользователь не авторизован")
	}
	
	var user User
	err := db.QueryRow("SELECT id, username, role FROM users WHERE id = ?", userID).Scan(
		&user.ID, &user.Username, &user.Role)
	if err != nil {
		return nil, err
	}
	
	return &user, nil
}

// requireAuth middleware для проверки аутентификации
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "user-session")
		userID, ok := session.Values["user_id"].(int)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		
		// Проверяем, что пользователь существует в базе
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&count)
		if err != nil || count == 0 {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		
		next(w, r)
	}
}

// requireAdmin middleware для проверки прав администратора
func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "user-session")
		userID, ok := session.Values["user_id"].(int)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		
		// Проверяем роль пользователя
		var role string
		err := db.QueryRow("SELECT role FROM users WHERE id = ?", userID).Scan(&role)
		if err != nil || role != "admin" {
			http.Redirect(w, r, "/user", http.StatusSeeOther)
			return
		}
		
		next(w, r)
	}
}

//обработка страниц
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")
		
		// Валидация
		errors := []string{}
		
		if !validateUsername(username) {
			errors = append(errors, "Логин должен содержать не менее 5 символов и состоять только из английских букв, цифр, _ и -")
		}
		
		if !validatePassword(password) {
			errors = append(errors, "Пароль должен содержать не менее 8 символов")
		}
		
		if password != confirmPassword {
			errors = append(errors, "Пароли не совпадают")
		}
		
		if len(errors) > 0 {
			data := map[string]interface{}{
				"Username": username,
				"Errors":   errors,
			}
			templates["register"].Execute(w, data)
			return
		}
		
		// Создаем юзера
		err := createUser(username, password, "user")
		if err != nil {
			errors = append(errors, err.Error())
			data := map[string]interface{}{
				"Username": username,
				"Errors":   errors,
			}
			templates["register"].Execute(w, data)
			return
		}
		
		//перенаправляем на страницу входа
		http.Redirect(w, r, "/login?registered=true", http.StatusSeeOther)
		return
	}
	
	// GET запрос - показываем форму регистрации
	templates["register"].Execute(w, nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		
		user, err := authenticate(username, password)
		if err != nil {
			data := map[string]interface{}{
				"Username": username,
				"Errors":   []string{err.Error()},
			}
			templates["login"].Execute(w, data)
			return
		}
		
		// Создаем сессию
		session, _ := store.Get(r, "user-session")
		session.Values["user_id"] = user.ID
		session.Save(r, w)
		
		// Перенаправляем в зависимости от роли
		if user.Role == "admin" {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/user", http.StatusSeeOther)
		}
		return
	}
	
	// GET запрос - показываем форму входа
	registered := r.URL.Query().Get("registered")
	data := map[string]interface{}{
		"Registered": registered == "true",
	}
	templates["login"].Execute(w, data)
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	
	data := map[string]interface{}{
		"User": user,
	}
	templates["user"].Execute(w, data)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromSession(r)
	if err != nil || user.Role != "admin" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")
		
		errors := []string{}
		
		if !validateUsername(username) {
			errors = append(errors, "Логин должен содержать не менее 5 символов и состоять только из английских букв, цифр, _ и -")
		}
		
		if !validatePassword(password) {
			errors = append(errors, "Пароль должен содержать не менее 8 символов")
		}
		
		if password != confirmPassword {
			errors = append(errors, "Пароли не совпадают")
		}
		
		if len(errors) > 0 {
			data := map[string]interface{}{
				"User":   user,
				"Errors": errors,
			}
			templates["admin"].Execute(w, data)
			return
		}
		
		// Создаем администратора
		err := createUser(username, password, "admin")
		if err != nil {
			errors = append(errors, err.Error())
			data := map[string]interface{}{
				"User":   user,
				"Errors": errors,
			}
			templates["admin"].Execute(w, data)
			return
		}
		
		// Успешное создание
		data := map[string]interface{}{
			"User":        user,
			"Success":     "Администратор успешно создан!",
		}
		templates["admin"].Execute(w, data)
		return
	}
	
	// GET запрос - показываем панель администратора
	templates["admin"].Execute(w, map[string]interface{}{"User": user})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "user-session")
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func main() {
	// Подключаемся к базе данных
	db = connectDB()
	defer db.Close()
	
	// Создаем первого администратора
	createFirstAdmin()
	
	// Инициализируем сессии
	store = sessions.NewCookieStore([]byte(generateSessionKey()))
	
	// Компилируем шаблоны
	initTemplates()
	
	// Создаем маршрутизатор
	r := mux.NewRouter()
	
	// Публичные маршруты
	r.HandleFunc("/register", registerHandler).Methods("GET", "POST")
	r.HandleFunc("/login", loginHandler).Methods("GET", "POST")
	r.HandleFunc("/logout", logoutHandler).Methods("GET")
	
	// Защищенные маршруты
	r.HandleFunc("/user", requireAuth(userHandler)).Methods("GET")
	r.HandleFunc("/admin", requireAdmin(requireAuth(adminHandler))).Methods("GET", "POST")
	
	log.Println("Сервер запущен на http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}