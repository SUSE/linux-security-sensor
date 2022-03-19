/*
   Velociraptor - Hunting Evil
   Copyright (C) 2019 Velocidex Innovations.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package authenticators

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	jwt "github.com/golang-jwt/jwt"
	"github.com/gorilla/csrf"
	"github.com/sirupsen/logrus"
	context "golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"www.velocidex.com/golang/velociraptor/acls"
	api_proto "www.velocidex.com/golang/velociraptor/api/proto"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/constants"
	gui_assets "www.velocidex.com/golang/velociraptor/gui/velociraptor"
	"www.velocidex.com/golang/velociraptor/json"
	"www.velocidex.com/golang/velociraptor/logging"
	users "www.velocidex.com/golang/velociraptor/users"
)

const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

type GoogleAuthenticator struct{}

var (
	unauthenticatedTemplateFileName = "/unauthenticated.html.tmpl"
	unauthorizedTemplateFileName = "/unauthorized.html.tmpl"
	logoffTemplateFileName = "/logoff.html.tmpl"
)

func (self *GoogleAuthenticator) AddHandlers(config_obj *config_proto.Config, mux *http.ServeMux) error {
	mux.Handle("/auth/google/login", oauthGoogleLogin(config_obj))
	mux.Handle("/auth/google/callback", oauthGoogleCallback(config_obj))

	return installLogoff(config_obj, mux)
}

func (self *GoogleAuthenticator) IsPasswordLess() bool {
	return true
}

// Check that the user is proerly authenticated.
func (self *GoogleAuthenticator) AuthenticateUserHandler(
	config_obj *config_proto.Config,
	parent http.Handler) (http.Handler, error) {

	return authenticateUserHandle(
		config_obj, parent, "/auth/google/login", "Google")
}

func oauthGoogleLogin(config_obj *config_proto.Config) http.Handler {
	authenticator := config_obj.GUI.Authenticator

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var googleOauthConfig = &oauth2.Config{
			RedirectURL:  config_obj.GUI.PublicUrl + "auth/google/callback",
			ClientID:     authenticator.OauthClientId,
			ClientSecret: authenticator.OauthClientSecret,
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
			Endpoint:     google.Endpoint,
		}

		// Create oauthState cookie
		oauthState, err := r.Cookie("oauthstate")
		if err != nil {
			oauthState = generateStateOauthCookie(w)
		}

		u := googleOauthConfig.AuthCodeURL(oauthState.Value, oauth2.ApprovalForce)
		http.Redirect(w, r, u, http.StatusTemporaryRedirect)
	})
}

func generateStateOauthCookie(w http.ResponseWriter) *http.Cookie {
	// Do not expire from the browser - we will expire it anyway.
	var expiration = time.Now().Add(365 * 24 * time.Hour)

	b := make([]byte, 16)
	_, _ = rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{
		Name:     "oauthstate",
		Value:    state,
		Secure:   true,
		HttpOnly: true,
		Expires:  expiration}
	http.SetCookie(w, &cookie)

	return &cookie
}

func oauthGoogleCallback(config_obj *config_proto.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read oauthState from Cookie
		oauthState, _ := r.Cookie("oauthstate")

		if r.FormValue("state") != oauthState.Value {
			logging.GetLogger(config_obj, &logging.GUIComponent).
				Error("invalid oauth google state")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		data, err := getUserDataFromGoogle(
			r.Context(), config_obj, r.FormValue("code"))
		if err != nil {
			logging.GetLogger(config_obj, &logging.GUIComponent).
				WithFields(logrus.Fields{
					"err": err,
				}).Error("getUserDataFromGoogle")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		user_info := &api_proto.VelociraptorUser{}
		err = json.Unmarshal(data, &user_info)
		if err != nil {
			logging.GetLogger(config_obj, &logging.GUIComponent).
				WithFields(logrus.Fields{
					"err": err,
				}).Error("getUserDataFromGoogle")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		// Create a new token object, specifying signing method and the claims
		// you would like it to contain.
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": user_info.Email,
			// Required re-auth after one day.
			"expires": float64(time.Now().AddDate(0, 0, 1).Unix()),
			"picture": user_info.Picture,
		})

		// Sign and get the complete encoded token as a string using the secret
		tokenString, err := token.SignedString(
			[]byte(config_obj.Frontend.PrivateKey))
		if err != nil {
			logging.GetLogger(config_obj, &logging.GUIComponent).
				WithFields(logrus.Fields{
					"err": err,
				}).Error("getUserDataFromGoogle")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		// Set the cookie and redirect.
		cookie := &http.Cookie{
			Name:     "VelociraptorAuth",
			Value:    tokenString,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			Expires:  time.Now().AddDate(0, 0, 1),
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})
}

func getUserDataFromGoogle(
	ctx context.Context,
	config_obj *config_proto.Config,
	code string) ([]byte, error) {
	authenticator := config_obj.GUI.Authenticator
	// Use code to get token and get user info from Google.
	var googleOauthConfig = &oauth2.Config{
		RedirectURL:  config_obj.GUI.PublicUrl + "auth/google/callback",
		ClientID:     authenticator.OauthClientId,
		ClientSecret: authenticator.OauthClientSecret,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}

	token, err := googleOauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}
	response, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()

	contents, err := ioutil.ReadAll(
		io.LimitReader(response.Body, constants.MAX_MEMORY))
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}
	return contents, nil
}

type _templateArgs struct {
	// Used for Authentication/Authorization/Logoff
	Timestamp  int64
	Heading    string
	CsrfToken  string
	BasePath   string
	UserTheme  string

	// Only for Unauthenticated/Authorization failure
	// Providing these to Logoff requires more plumbing
	LoginUrl   string
	Provider   string

	// Only for Authorization failure
	Username   string
	Error      string
}

var defaultLogoffTemplate string = `
<html><body>
You have successfully logged off!
</body></html>
`

// This will _not_ do variable substitution
var fallbackLogoffMessage string = defaultLogoffTemplate

func installLogoff(config_obj *config_proto.Config, mux *http.ServeMux) error {

	base := config_obj.GUI.BasePath

	logoffTemplate, err := parseTemplate(config_obj, logoffTemplateFileName, defaultLogoffTemplate)
	if err != nil {
		return err
	}

	// On logoff just clear the cookie and redirect.
	mux.Handle("/logoff", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		var user_options *api_proto.SetGUIOptionsRequest

		params := r.URL.Query()
		old_username, ok := params["username"]
		if ok && len(old_username) == 1 {
			logger := logging.GetLogger(config_obj, &logging.Audit)
			logger.Info("Logging off %v", old_username[0])
			user_options, _ = users.GetUserOptions(config_obj, old_username[0])
		}

		if user_options == nil {
			// Fallback
			user_options = &api_proto.SetGUIOptionsRequest{}
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "VelociraptorAuth",
			Path:     "/",
			Value:    "",
			Secure:   true,
			HttpOnly: true,
			Expires:  time.Unix(0, 0),
		})

		templateArgs := _templateArgs{
				Timestamp: time.Now().UTC().UnixNano() / 1000,
				CsrfToken: csrf.Token(r),
				BasePath:  base,
				Heading:   "Heading",
				UserTheme: user_options.Theme,
		}

		err = logoffTemplate.Execute(&buf, templateArgs)
		if err != nil {
			logger := logging.GetLogger(config_obj, &logging.GUIComponent)
			logger.Error("Failed to execute template logoffTemplate: %v", err)

			// HTTP spec says clients must honor cookies unless the status code is 1xx
			http.Error(w, fallbackLogoffMessage,
				   http.StatusInternalServerError)
			return
		}

		buf.WriteTo(w)
	}))

	return nil
}

var defaultUnauthenticatedTemplate string = `
<html><body>
<h1>Authentication required</h1>
<p>This system is unavailable to unauthenticated users.</p>
<p><a href="{{.LoginUrl}}" style="text-transform:none">
        Login with {{.Provider}}
      </a></p>
</body></html>
`

var defaultUnauthorizedTemplate string = `
<html><body>
<h1>Authorization failed</h1>
Authorization failed. The account {{.Username}} does not exist or does not have sufficient persmissions.
Contact your system administrator to get an account, or click here
to log in again:

      <a href="{{.LoginUrl}}" style="text-transform:none">
        Login with {{.Provider}}
      </a>
</body></html>
`

func parseTemplate(config_obj *config_proto.Config, templatePath string,
		   fallbackTemplate string) (*template.Template, error) {
	var tmpl *template.Template

	guiLogger := logging.GetLogger(config_obj, &logging.GUIComponent)

	data, err := gui_assets.ReadFile(templatePath)
	if err == nil {
		tmpl, err := template.New("").Parse(string(data))
		if err != nil {
			return nil, fmt.Errorf("Failed to parse template %s: %v", templatePath, err)
		}

		return tmpl, nil
	}

	guiLogger.Error("Failed to read %s from gui assets, using built-in default. Reason: %v",
			templatePath, err)

	tmpl, err = template.New("").Parse(fallbackTemplate)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse fallback template for %s. Reason: %v",
				       templatePath, err)
	}

	return tmpl, nil
}

func authenticateUserHandle(config_obj *config_proto.Config,
	parent http.Handler, login_url string, provider string) (http.Handler, error) {

	guiLogger := logging.GetLogger(config_obj, &logging.GUIComponent)

	unauthenticatedTemplate, err := parseTemplate(config_obj, unauthenticatedTemplateFileName,
						      defaultUnauthenticatedTemplate)
	if err != nil {
		return nil, err
	}

	unauthorizedTemplate, err := parseTemplate(config_obj, unauthorizedTemplateFileName,
						   defaultUnauthorizedTemplate)
	if err != nil {
		return nil, err
	}

	base := config_obj.GUI.BasePath

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-CSRF-Token", csrf.Token(r))

		// Unauthenticated users have no options
		user_options := &api_proto.SetGUIOptionsRequest{}

		templateArgs := _templateArgs{
				Timestamp: time.Now().UTC().UnixNano() / 1000,
				CsrfToken: csrf.Token(r),
				BasePath:  base,
				Heading:   "Heading",
				UserTheme: user_options.Theme,
				LoginUrl: login_url,
				Provider: provider,
		}

		// Reject by returning 401 and displaying an authenticated user message
		// with link to authenticate
		reject := func(err error) {
			var buf bytes.Buffer

			tmplErr := unauthenticatedTemplate.Execute(&buf, templateArgs)
			if tmplErr != nil {
				http.Error(w, "Failed to format page",
					   http.StatusInternalServerError)
				guiLogger.Error("Failed to execute template unauthenticatedTemplate: %v", tmplErr)
				return
			}

			w.WriteHeader(http.StatusUnauthorized)
			buf.WriteTo(w)

			// We don't really need to log every unauthenticated user, do we?
		}

		// Reject by returning 401 and displaying a login failure with option
		// to reauthenticate
		reject_with_username := func(err error, username string) {
			var buf bytes.Buffer

			logging.GetLogger(config_obj, &logging.Audit).
				WithFields(logrus.Fields{
					"user":   username,
					"remote": r.RemoteAddr,
					"method": r.Method,
				}).Error("User rejected by GUI")

			templateArgs.Username = username
			templateArgs.Error = err.Error()

			tmplErr := unauthorizedTemplate.Execute(&buf, templateArgs)
			if tmplErr != nil {
				http.Error(w, "Failed to format page",
					   http.StatusInternalServerError)
				guiLogger.Error("Failed to execute template unauthorizedTemplate: %v", tmplErr)
				return
			}

			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			buf.WriteTo(w)

		}

		// We store the user name and their details in a local
		// cookie. It is stored as a JWT so we can trust it.
		auth_cookie, err := r.Cookie("VelociraptorAuth")
		if err != nil {
			reject(err)
			return
		}

		// Parse the JWT.
		token, err := jwt.Parse(
			auth_cookie.Value,
			func(token *jwt.Token) (interface{}, error) {
				_, ok := token.Method.(*jwt.SigningMethodHMAC)
				if !ok {
					return nil, errors.New("invalid signing method")
				}
				return []byte(config_obj.Frontend.PrivateKey), nil
			})
		if err != nil {
			reject(err)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			reject(errors.New("token not valid"))
			return
		}

		// Record the username for handlers lower in the
		// stack.
		username, pres := claims["user"].(string)
		if !pres {
			reject(errors.New("username not present"))
			return
		}

		// Check if the claim is too old.
		expires, pres := claims["expires"].(float64)
		if !pres {
			reject_with_username(errors.New("expires field not present in JWT"),
				username)
			return
		}

		if expires < float64(time.Now().Unix()) {
			reject_with_username(errors.New("the JWT is expired - reauthenticate"),
				username)
			return
		}

		picture, _ := claims["picture"].(string)

		// Now check if the user is allowed to log in.
		user_record, err := users.GetUser(config_obj, username)
		if err != nil {
			reject_with_username(errors.New("Invalid user"), username)
			return
		}

		// Must have at least reader permission.
		perm, err := acls.CheckAccess(config_obj, username, acls.READ_RESULTS)
		if !perm || err != nil || user_record.Locked || user_record.Name != username {
			reject_with_username(errors.New("Insufficient permissions"), username)
			return
		}

		// Checking is successful - user authorized. Here we
		// build a token to pass to the underlying GRPC
		// service with metadata about the user.
		user_info := &api_proto.VelociraptorUser{
			Name:    username,
			Picture: picture,
		}

		// Must use json encoding because grpc can not handle
		// binary data in metadata.
		serialized, _ := json.Marshal(user_info)
		ctx := context.WithValue(
			r.Context(), constants.GRPC_USER_CONTEXT, string(serialized))

		// Need to call logging after auth so it can access
		// the contextKeyUser value in the context.
		GetLoggingHandler(config_obj)(parent).ServeHTTP(
			w, r.WithContext(ctx))
	}), nil
}
