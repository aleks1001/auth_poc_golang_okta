package config

import "net/http"

type DatabaseConfig struct {
	Type         string
	Host         string
	Port         int
	User         string
	Password     string
	DatabaseName string
	MaxIdleConns int
	MaxOpenConns int
}

// OauthConfig stores oauth service configuration options
type OauthConfig struct {
	AccessTokenLifetime  int
	RefreshTokenLifetime int
	AuthCodeLifetime     int
}

// SessionConfig stores session configuration for the web app
type SessionConfig struct {
	Secret string
	Path   string
	// MaxAge=0 means no 'Max-Age' attribute specified.
	// MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'.
	// MaxAge>0 means Max-Age attribute present and given in seconds.
	MaxAge int
	// When you tag a cookie with the HttpOnly flag, it tells the browser that
	// this particular cookie should only be accessed by the server.
	// Any attempt to access the cookie from client script is strictly forbidden.
	HTTPOnly bool
	SameSite http.SameSite
}

// Config stores all configuration options
type Config struct {
	Database      DatabaseConfig
	Oauth         OauthConfig
	Session       SessionConfig
	IsDevelopment bool
}

func NewConfig() *Config {
	return &Config{
		Database: DatabaseConfig{
			Type:         "mysql",
			Host:         "127.0.0.1",
			Port:         3306,
			User:         "root",
			Password:     "root",
			DatabaseName: "cabernet",
			MaxIdleConns: 10,
			MaxOpenConns: 100,
		},
		Oauth: OauthConfig{
			AccessTokenLifetime:  3600,    // 1 hour
			RefreshTokenLifetime: 1209600, // 14 days
			AuthCodeLifetime:     3600,    // 1 hour
		},
		Session: SessionConfig{
			Path:     "/",
			MaxAge:   60, // 60 sec
			HTTPOnly: true,
			SameSite: http.SameSiteLaxMode,
		},
		IsDevelopment: true,
	}
}
