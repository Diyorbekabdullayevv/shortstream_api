package dbConnect

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func ConnectDB() (*sql.DB, error) {

	dbPassword := os.Getenv("DB_PASSWORD")
	dbUrl := os.Getenv("DB_URL")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf("postgres://postgres:%v@%v%v/%v", dbPassword, dbUrl, dbPort, dbName)
	// dsn := fmt.Sprintf("postgres://postgres:dev_diego@localhost:5433/shortstream")

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal("Failed to open connection:", err)
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	fmt.Println("✅ Connected to PostgreSQL successfully!")
	return db, nil
}
