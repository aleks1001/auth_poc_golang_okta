package main

import (
	"./bbi"
	"./config"
	"./database"
	"./okta"
	util "./util"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

type Env struct {
	db         *gorm.DB
	session    *sessions.CookieStore
	OKTAClient *okta.Client
}

var tpl *template.Template
var env *Env
var samlSP *samlsp.Middleware

type User struct {
	bbi.User
	RedirectURI     string `json:"redirectURI"`
	IsAuthenticated bool   `json:"isAuthenticated"`
}

func init() {
	util.ParseEnvironment()
	gob.Register(&User{})
	tpl = template.Must(template.ParseGlob("templates/*"))
}

func initSessionStore() *sessions.CookieStore {
	authKeyOne := securecookie.GenerateRandomKey(64)
	encryptionKeyOne := securecookie.GenerateRandomKey(32)
	store := sessions.NewCookieStore(
		authKeyOne,
		encryptionKeyOne,
	)
	store.Options = &sessions.Options{
		MaxAge:   60,
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}
	return store
}

func main() {
	keyPair, err := tls.LoadX509KeyPair("myservice.cert", "myservice.key")
	if err != nil {
		panic(err) // TODO handle error
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadataURL, err := url.Parse("https://dev-250162.okta.com/app/exkalp2dmli2yiRs74x6/sso/saml/metadata")
	if err != nil {
		panic(err) // TODO handle error
	}

	rootURL, err := url.Parse("http://localhost:8080?redirect_uri=http://localhost:3000/feature")
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		panic(err) // TODO handle error
	}

	samlSP, _ = samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
	})

	c := config.NewConfig()
	db, err := database.NewDatabase(c)
	if err != nil {
		log.Fatal("Cannot open DB connection: ", err.Error())
	}
	defer db.Close()

	conf := &okta.OIDCConfig{
		Issuer:       os.Getenv("ISSUER"),
		ClientId:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectUri:  os.Getenv("REDIRECT_URI"),
	}
	env = &Env{
		db:         db,
		OKTAClient: okta.NewClient(conf),
		session:    initSessionStore(),
	}

	if err := env.OKTAClient.GetMetadata(); err != nil {
		log.Printf("Cannot initial Okta metadata call.")
		os.Exit(1)
	}
	fmt.Printf("Okta call succesful for ISSUER %s \n", env.OKTAClient.Metadata.Issuer)

	r := mux.NewRouter()
	// OKTA Specific
	//r.Handle("/home", homeHandler(env)).Methods(http.MethodGet)
	r.Handle("/authorize", authorizeHandler(env)).Methods(http.MethodPost)
	r.Handle("/v1/ingestion/idpResponse", implicitCallback(env)).Methods(http.MethodGet)
	//r.Handle("/profile", profileHandler(env)).Methods(http.MethodGet)

	// Custom Login Specific
	r.Handle("/", indexHandler(env)).Methods(http.MethodGet)
	r.Handle("/login", loginHandler(env)).Methods(http.MethodPost, http.MethodOptions)
	r.Handle("/introspect", introspectHandler(env)).Methods(http.MethodPost, http.MethodOptions)

	// SAML 2.0
	//app := http.HandlerFunc(hello)
	//samlSP.Binding = saml.HTTPRedirectBinding
	//r.Handle("/hello", samlSP.RequireAccount(app))
	//r.Handle("/saml/acs", samlSP)
	r.Handle("/saml/acs", samlResponse(env)).Methods(http.MethodPost)
	r.Handle("/saml_auth", samlRedirect(env)).Methods(http.MethodPost)

	r.Use(mux.CORSMethodMiddleware(r))
	server := &http.Server{
		Handler:      r,
		Addr:         "localhost:8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

// SAML
func hello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %s!", "world")
}
func samlRedirect(env *Env) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		binding := saml.HTTPPostBinding
		bindingLocation := samlSP.ServiceProvider.GetSSOBindingLocation(binding)
		authReq, err := samlSP.ServiceProvider.MakeAuthenticationRequest(bindingLocation)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		post, err := samlSP.RequestTracker.TrackRequest(w, r, authReq.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Add("Content-Security-Policy", ""+
			"default-src; "+
			"script-src 'sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE='; "+
			"reflected-xss block; referrer no-referrer;")
		w.Header().Add("Content-type", "text/html")
		w.Write([]byte(`<!DOCTYPE html><html><body>`))
		w.Write(authReq.Post(post))
		w.Write([]byte(`</body></html>`))
		return
	})
}

func samlResponse(env *Env) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		var possibleRequestIDs []string
		trackedRequests := samlSP.RequestTracker.GetTrackedRequests(r)
		for _, tr := range trackedRequests {
			possibleRequestIDs = append(possibleRequestIDs, tr.SAMLRequestID)
		}
		assertion, err := samlSP.ServiceProvider.ParseResponse(r, possibleRequestIDs)

		if err != nil {
			fmt.Println("ERROR: \n ", err.(*saml.InvalidResponseError).PrivateErr)
			_, _ = fmt.Fprintln(w, err.(*saml.InvalidResponseError).PrivateErr)
			return
		}

		url, _ := url.Parse(trackedRequests[0].URI)
		redirectURI := url.Query().Get("redirect_uri")
		//fmt.Printf("%+v\n", assertion.Subject.NameID.Value)

		var u bbi.User
		env.db.First(&u, "email = ?", assertion.Subject.NameID.Value)
		if u.Email != "" {
			session, err := env.session.Get(r, "SESSION_ID")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			user := User{
				User:            u,
				IsAuthenticated: true,
				RedirectURI:     redirectURI,
			}
			session.Values["user"] = user
			if err := session.Save(r, w); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			http.Redirect(w, r, redirectURI, http.StatusMovedPermanently)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})
}

func indexHandler(env *Env) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		redirectUri, err := getRedirectURI(r)
		if err != nil {
			_, _ = fmt.Fprintln(w, err.Error())
			return
		}

		if isAuth, session := isAuthenticated(env.session, r); isAuth {
			userObject := session.Values["user"]
			if user, ok := userObject.(*User); ok {
				http.Redirect(w, r, user.RedirectURI, http.StatusMovedPermanently)
				return
			}
			_, _ = fmt.Fprintln(w, "Cannot read session and retrieve User")
			return
		}
		data := &User{
			RedirectURI: redirectUri,
		}
		renderTemplate(w, "signin.gohtml", data)
	})
}

func loginHandler(env *Env) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectURI, err := getRedirectURI(r)
		if err != nil {
			_, _ = fmt.Fprintln(w, err.Error())
			return
		}

		if err := r.ParseForm(); err != nil {
			_, _ = fmt.Fprintln(w, "Cannot parse Login form")
			return
		}

		var u bbi.User
		email := r.FormValue("email")
		password := r.FormValue("password")
		env.db.First(&u, "email = ?", email)

		if util.IsPasswordMatch(u.Password, password) {
			session, err := env.session.Get(r, "SESSION_ID")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			user := User{
				User:            u,
				IsAuthenticated: true,
				RedirectURI:     redirectURI,
			}
			session.Values["user"] = user
			if err := session.Save(r, w); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			http.Redirect(w, r, redirectURI, http.StatusMovedPermanently)
			return
		}
		http.Redirect(w, r, "/", http.StatusMovedPermanently)
	})
}

func introspectHandler(env *Env) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		authServer := "http://localhost:8080"
		q := r.URL.Query()
		q.Add("redirect_uri", r.Header.Get("Referer"))

		user := &User{
			IsAuthenticated: false,
			RedirectURI:     authServer + "?" + q.Encode(),
		}

		if isAuth, session := isAuthenticated(env.session, r); isAuth {
			userObject := session.Values["user"]
			if user, ok := userObject.(*User); ok {
				user.IsAuthenticated = true
				writeJSON(w, user, 200)
				return
			}
			fmt.Fprint(w, "Cannot parse value from the session")
		}
		writeJSON(w, user, 200)
	})
}

// OKTA Specific
//func homeHandler(env *Env) http.Handler {
//	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		data := new(customData)
//		if isAuth, session := isAuthenticated(env.session, r); isAuth {
//			accessToken := session.Values["access_token"].(string)
//			profile, err := env.OKTAClient.GetUserProfile(accessToken)
//			if err != nil {
//				http.Error(w, err.Error(), http.StatusInternalServerError)
//			}
//			data.Profile = profile
//			data.IsAuthenticated = isAuth
//		}
//		if err := tpl.ExecuteTemplate(w, "home.gohtml", data); err != nil {
//			http.Error(w, err.Error(), http.StatusInternalServerError)
//		}
//	})
//}

func authorizeHandler(env *Env) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectURI, err := getRedirectURI(r)
		if err != nil {
			_, _ = fmt.Fprintln(w, err.Error())
			return
		}
		redirectPath := env.OKTAClient.GetAuthorizeURI(r, redirectURI)
		http.Redirect(w, r, redirectPath, http.StatusMovedPermanently)
	})
}

func implicitCallback(env *Env) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != env.OKTAClient.State {
			_, _ = fmt.Fprintln(w, "The state was not as expected")
			return
		}

		redirectURI := string(util.DecodeBase64(r.URL.Query().Get("state")))

		if r.URL.Query().Get("code") == "" {
			_, _ = fmt.Fprintln(w, "The code was not returned or is not accessible")
			return
		}

		if err := env.OKTAClient.GetExchangeCode(r.URL.Query().Get("code"), r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		session, err := env.session.Get(r, "SESSION_ID")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		session.Values["user"] = User{
			IsAuthenticated: true,
			RedirectURI:     redirectURI,
			User: bbi.User{
				FirstName: "Tom",
				LastName:  "Cook",
				Email:     "bbiadmin@blackboardinsurance.com",
			},
		}
		if err := session.Save(r, w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		http.Redirect(w, r, redirectURI, http.StatusMovedPermanently)
	})
}

//func profileHandler(env *Env) http.Handler {
//	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		data := new(customData)
//		if isAuth, session := isAuthenticated(env.session, r); isAuth {
//			accessToken := session.Values["access_token"].(string)
//			profile, err := env.OKTAClient.GetUserProfile(accessToken)
//			if err != nil {
//				_, _ = fmt.Fprint(w, err.Error())
//			}
//			data.Profile = profile
//			data.IsAuthenticated = isAuth
//			data.IdToken = session.Values["id_token"]
//			data.AccessToken = accessToken
//			data.IQOSToken = env.OKTAClient.IQOSClient.AuthResponse.AccessToken
//			_ = tpl.ExecuteTemplate(w, "profile.gohtml", data)
//			return
//		}
//		http.Redirect(w, r, "/", http.StatusMovedPermanently)
//	})
//}

func isAuthenticated(s *sessions.CookieStore, r *http.Request) (bool, *sessions.Session) {
	session, err := s.Get(r, "SESSION_ID")
	if err != nil || session.Values["user"] == nil || session.Values["user"] == "" {
		return false, nil
	}
	return true, session
}

//func LogoutHandler(w http.ResponseWriter, r *http.Request) {
//	session, err := sessionStore.Get(r, "okta-session")
//	if err != nil {
//		http.Error(w, err.Error(), http.StatusInternalServerError)
//	}
//
//	//q := r.URL.Query()
//	//q.Add("id_token_hint", session.Values["id_token"].(string))
//	//q.Add("post_logout_redirect_uri", os.Getenv("REDIRECT_LOGOUT_URI"))
//
//	delete(session.Values, "id_token")
//	delete(session.Values, "access_token")
//
//	if err := session.Save(r, w); err != nil {
//		http.Error(w, err.Error(), http.StatusInternalServerError)
//	}
//
//	oktaClient.IQOSClient.Quit <- false
//	http.Redirect(w, r, "/", http.StatusMovedPermanently)
//}

//func handleTSIQ(w http.ResponseWriter, r *http.Request) {
//	subs, err := oktaClient.IQOSClient.GetPolicyTransactions()
//
//	fmt.Println(subs)
//
//	//js, err := json.Marshal(oktaClient.IQOSClient.PolicyTransactions)
//	if err != nil {
//		http.Error(w, err.Error(), http.StatusInternalServerError)
//		return
//	}
//	w.Header().Set("Content-Type", "application/json")
//	w.Write([]byte(""))
//}

// WriteJSON writes JSON response
func writeJSON(w http.ResponseWriter, v interface{}, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func getRedirectURI(r *http.Request) (string, error) {
	if r.URL.Query().Get("redirect_uri") == "" {
		return "", errors.New("Redirect URI must be provided")
	}

	redirectURI, err := url.Parse(r.URL.Query().Get("redirect_uri"))
	if err != nil {
		return "", errors.New("Invalid Redirect URI was provided")
	}
	return redirectURI.String(), nil
}

func renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	if err := tpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
