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
	Login    string
	Password string
	Role     string
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

func VerifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
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

func verifyUser(w http.ResponseWriter, req *http.Request) {
	type Responce struct {
		jwt  []byte `"json": JWTocken`
		role string `"json": role`
	}

	formData := postParser(w, req)

	user, err := GetUserData(formData["login"])
	if err != nil || user == nil {
		fmt.Fprint(w, err)
		http.Error(w, "Неверный логин", http.StatusUnauthorized)
		return
	}

	err = VerifyPassword(user.Password, formData["password"])
	if err != nil {
		fmt.Print(err)
		http.Error(w, "Неверный пароль", http.StatusUnauthorized)
		return
	}

	response := Responce{
		jwt:  createJWTocken(w, *user),
		role: user.Role,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		fmt.Print("1")
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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

func deleteUser(w http.ResponseWriter, req *http.Request) {

}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/registration", createUser)
	mux.HandleFunc("/api/verifyUser", verifyUser)
	mux.HandleFunc("/api/getStandartScoreStat", getStandartStat)
	mux.HandleFunc("/api/getRegions", getRegions)
	mux.HandleFunc("/api/getFireTypes", getFireTypes)

	http.ListenAndServe(":8080", mux)
}
