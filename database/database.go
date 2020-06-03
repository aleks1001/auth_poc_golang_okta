package database

import (
	"../config"
	"fmt"
	"github.com/jinzhu/gorm"
	"time"
	// Drivers
	_ "github.com/go-sql-driver/mysql"
)

func init() {
	gorm.NowFunc = func() time.Time {
		return time.Now().UTC()
	}
}

// NewDatabase returns a gorm.DB struct, gorm.DB.DB() returns a database handle
// see http://golang.org/pkg/database/sql/#DB
func NewDatabase(cnf *config.Config) (*gorm.DB, error) {
	// mysql way
	if cnf.Database.Type == "mysql" {
		args := fmt.Sprintf(
			"%s:%s@tcp(%s:%d)/%s",
			cnf.Database.User,
			cnf.Database.Password,
			cnf.Database.Host,
			cnf.Database.Port,
			cnf.Database.DatabaseName,
		)

		db, err := gorm.Open(cnf.Database.Type, args)
		if err != nil {
			return db, err
		}

		// Max idle connections
		db.DB().SetMaxIdleConns(cnf.Database.MaxIdleConns)

		// Max open connections
		db.DB().SetMaxOpenConns(cnf.Database.MaxOpenConns)

		// Database logging
		db.LogMode(cnf.IsDevelopment)

		return db, nil
	}

	// Database type not supported
	return nil, fmt.Errorf("Database type %s not suppported", cnf.Database.Type)
}
