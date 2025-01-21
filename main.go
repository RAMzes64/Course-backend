package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Login    string `json: "login"`
	Password string `json: "password"`
	Role     string `json: "role"`
}

var (
	secretKey = []byte("ключ")
)

// хеширования пароля с "солью"
func HashPassword(password string) (string, error) {
	// Комбинирование пароли и соли и хэширование
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
}

func verifyUser(formData map[string]string) (*User, error) {
	user, err := GetUserData(formData["login"])
	if err != nil || user == nil {
		return nil, err
	}

	err = VerifyPassword(user.Password, formData["password"])
	if err != nil {
		return nil, err
	}

	return user, nil
}

func VerifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func verifyJWT(w http.ResponseWriter, req *http.Request) bool {
	tokenString := req.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Токен не предоставлен", http.StatusUnauthorized)
		return false
	}

	// Проверка токена
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("неверный метод подписи: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil || !parsedToken.Valid {
		http.Error(w, "Недействительный токен", http.StatusUnauthorized)
		fmt.Fprintf(w, "\n%s\n%s", err, !parsedToken.Valid)
		return false
	}

	// Если токен действителен, можно получить данные
	if _, ok := parsedToken.Claims.(jwt.MapClaims); ok {
		fmt.Fprint(w, "Все ок")
		return true
	}
	return false
}

func createJWTocken(w http.ResponseWriter, user User) []byte {
	// Создание токена
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": user.Login,                            // login
		"role": user.Role,                             // role
		"iss":  time.Now().Add(time.Hour * 72).Unix(), // Issued at
	})

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		fmt.Fprint(w, err)
		http.Error(w, "Ошибка при создании токена", http.StatusInternalServerError)
	}

	JWTocken, err := json.Marshal(tokenString)
	return JWTocken
}

func loginValidation(w http.ResponseWriter, req *http.Request) {
	formData := postParser(w, req)
	user, err := verifyUser(formData)
	if err != nil {
		http.Error(w, "Неверный логин или пароль", http.StatusUnauthorized)
	}
	json, err := json.Marshal(user.Role)
	w.Write(json)
}

func createUser(w http.ResponseWriter, req *http.Request) {
	formData := postParser(w, req)

	err := CreateUser(formData)

	if err != nil {
		switch err.Error() {
		case "500":
			http.Error(w, "Ошибка при работе с базой данных", http.StatusInternalServerError)
		case "400":
			http.Error(w, "Неверный логин", http.StatusUnauthorized)

		default:
			fmt.Fprint(w, err)
		}
	}

}

// Парсер post запроса
func postParser(w http.ResponseWriter, req *http.Request) map[string]string {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return nil
	}
	err := req.ParseForm() // Парсим форму

	if err != nil {
		http.Error(w, "Ошибка парсинга формы", http.StatusBadRequest)
		return nil
	}

	formData := map[string]string{}
	for key, value := range req.Form {
		if len(value) > 0 {
			formData[key] = value[0]
		}
	}
	return formData
}

func getRegions(w http.ResponseWriter, req *http.Request) {
	jsonData, err := GetRegions()

	if err != nil {
		fmt.Fprintf(w, "Возникла ошибка: %s", err)
		return
	}

	w.Write(jsonData)
}

func getFireTypes(w http.ResponseWriter, req *http.Request) {
	jsonData, err := GetFireTypes()

	if err != nil {
		fmt.Fprintf(w, "Возникла ошибка: %s", err)
		return
	}

	w.Write(jsonData)
}

func getStandartStat(w http.ResponseWriter, req *http.Request) {
	formData := postParser(w, req)

	var (
		jsonData []byte
		err      error
	)

	if len(formData) > 1 {
		jsonData, err = GetStandartStat(formData)
	} else {
		jsonData, err = GetStandartStatWithTypes(formData)
	}

	if err != nil {
		fmt.Fprintf(w, "Возникла ошибка: %s", err)
		return
	}

	w.Write(jsonData)
}

func addData(w http.ResponseWriter, req *http.Request) {
	fmt.Println("Работает1")
	formData := postParser(w, req)
	user, err := verifyUser(formData)
	if user == nil || err != nil {
		fmt.Println("Не работает1")
		fmt.Fprintf(w, "error: %s, user: %s")
		return
	}

	err = InsertIntoFires(formData, user.Login)
	if err != nil {
		fmt.Printf("Не работает2 %s", err)
		http.Error(w, "Неверный формат данных", http.StatusBadRequest)
		return
	}
	response, err := json.Marshal("ok")
	w.Write(response)
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/registration", createUser)
	mux.HandleFunc("/api/verifyUser", loginValidation)
	mux.HandleFunc("/api/getStandartScoreStat", getStandartStat)
	mux.HandleFunc("/api/getRegions", getRegions)
	mux.HandleFunc("/api/getFireTypes", getFireTypes)
	mux.HandleFunc("/api/addData", addData)

	http.ListenAndServe(":8080", mux)
}
