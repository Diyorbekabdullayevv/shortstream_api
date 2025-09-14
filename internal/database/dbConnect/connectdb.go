package dbConnect

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func ConnectDB() (*sql.DB, error) {

	// Adjust user, password, dbname, port
	dsn := "postgres://postgres:dev_diego@localhost:5433/shortstream"

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
