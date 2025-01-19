package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"
)

type database struct {
	connection *sql.DB
}

var (
	instance *database
	once     sync.Once
)

func getInstance() (*database, error) {
	var err error
	once.Do(func() {
		instance = &database{}
		instance.connection, err = sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/courseDB")
		if err != nil {
			instance = nil // Если ошибка, сбрасываем экземпляр
		}
	})
	return instance, err
}

func CreateUser(formData map[string]string) error {
	db, err := getInstance()

	if err != nil {
		return errors.New("500")
	}

	if !loginNameValidation(formData["login"]) {
		return errors.New("400")
	}

	formData["password"], err = HashPassword(formData["password"])
	if err != nil {
		return err
	}

	_, err = db.connection.Exec(`INSERT INTO users(login, password) VALUES (?, ?)`, formData["login"], formData["password"])

	if err != nil {
		return err
	}

	return nil
}

func GetUserData(login string) (*User, error) {
	db, err := getInstance()
	if err != nil {
		return nil, err
	}

	if sqlValidation(login) {
		return nil, nil
	}

	result, err := db.connection.Query(`SELECT login, password, role FROM users WHERE login = ?`, login)

	if err != nil {
		fmt.Println("Пока все норм")

		return nil, err
	}
	user := new(User)

	if result.Next() {
		err = result.Scan(&user.Login, &user.Password, &user.Role)
		fmt.Println("Все ещё все норм")

		if err != nil {
			return nil, err
		}
		return user, nil
	}

	return nil, nil
}

func GetStandartStat(formData map[string]string) ([]byte, error) {
	db, err := getInstance()

	type StandartStatUnit struct {
		Fire_count     int
		Fire_date      string
		Standart_score float64
	}

	if err != nil {
		return nil, err
	}

	result, err := db.connection.Query(`CALL getStandartScore(?);`, formData["region_id"])

	if err != nil {
		return nil, err
	}

	dt := make([]*StandartStatUnit, 0)

	for result.Next() {
		data := new(StandartStatUnit)
		err = result.Scan(&data.Fire_count, &data.Fire_date, &data.Standart_score)

		if err != nil {
			return nil, err
		}

		dt = append(dt, data)
	}
	return json.Marshal(&dt) //Конвертируем в json

}

func GetRegions() ([]byte, error) {
	type Region struct {
		Region_id   int    `json: "region_id"`
		Region_name string `json: "region_id"`
	}

	db, err := getInstance()

	if err != nil {
		return nil, err
	}

	result, err := db.connection.Query("SELECT region_id, region_name FROM regions")

	if err != nil {
		return nil, err
	}

	dt := make([]*Region, 0)

	for result.Next() {
		data := new(Region)
		err = result.Scan(&data.Region_id, &data.Region_name)

		if err != nil {
			panic(err)
		}

		dt = append(dt, data)
	}
	return json.Marshal(&dt) //Конвертируем в json
}

func sqlValidation(input string) bool {
	matched, _ := regexp.MatchString(`;`, input)
	return matched
}

func loginNameValidation(login string) bool {
	mathed, _ := regexp.MatchString(`^[a-zA-Z]{1}\w{5,}$`, login)
	return mathed
}
