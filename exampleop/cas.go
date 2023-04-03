package exampleop

import (
	"context"
	"encoding/xml"
	"fmt"
	"github.com/axel7083/cas-to-openid-adapter/storage"
	"github.com/gorilla/mux"
	"golang.org/x/text/language"
	"io/ioutil"
	"net/http"
	"net/url"
)

type authenticate interface {
	ValidateRequest(user *storage.User, id string) error
}

type cas struct {
	store               authenticate
	casAddress          string
	casLoginEndpoint    string
	casValidateEndpoint string
	router              *mux.Router
	callback            string
	clientCallback      func(context.Context, string) string
}

type CasServiceResponse struct {
	XMLName               xml.Name                  `xml:"http://www.yale.edu/tp/cas serviceResponse"`
	AuthenticationSuccess *CasAuthenticationSuccess `xml:"authenticationSuccess,omitempty"`
	AuthenticationFailure *CasAuthenticationFailure `xml:"authenticationFailure,omitempty"`
}

type CasAuthenticationFailure struct {
	Code    string `xml:"code,attr"`
	Message string `xml:",chardata"`
}

type CasAuthenticationSuccess struct {
	User                               string `xml:"user" json:"user"`
	SsoId                              string `xml:"attributes>ssoId" json:"ssoId"`
	LastName                           string `xml:"attributes>lastName" json:"lastName"`
	Country                            string `xml:"attributes>country" json:"country"`
	EmailConfirmed                     bool   `xml:"attributes>emailConfirmed" json:"emailConfirmed"`
	Contactid                          string `xml:"attributes>contactid" json:"contactid"`
	HasRememberMe                      bool   `xml:"attributes>hasRememberMe" json:"hasRememberMe"`
	Telephone                          string `xml:"attributes>telephone" json:"telephone"`
	Employee                           int    `xml:"attributes>employee" json:"employee"`
	PasswordCreationTime               int    `xml:"attributes>passwordCreationTime" json:"passwordCreationTime"`
	UserId                             string `xml:"attributes>userId" json:"userId"`
	LastAuthenticationFromRepositories string `xml:"attributes>lastAuthenticationFromRepositories" json:"lastAuthenticationFromRepositories"`
	FirstName                          string `xml:"attributes>firstName" json:"firstName"`
	UserUuid                           string `xml:"attributes>user_uuid" json:"user_uuid"`
	Company                            string `xml:"attributes>company" json:"company"`
	Email                              string `xml:"attributes>email" json:"email"`
	TwoFaActive                        bool   `xml:"attributes>twoFaActive" json:"twoFaActive"`
	Username                           string `xml:"attributes>username" json:"username"`
}

func ConvertCasAuthenticationSuccessToUser(cas *CasAuthenticationSuccess) *storage.User {
	user := &storage.User{}

	user.ID = cas.UserId
	user.Username = cas.Username
	user.FirstName = cas.FirstName
	user.LastName = cas.LastName
	user.Email = cas.Email
	user.EmailVerified = cas.EmailConfirmed
	user.Phone = cas.Telephone
	user.PhoneVerified = false // not provided in CasAuthenticationSuccess struct
	user.IsAdmin = false       // not provided in CasAuthenticationSuccess struct

	// Convert the language tag string to a language.Tag value.
	if cas.Country != "" {
		user.PreferredLanguage = language.MustParse(cas.Country)
	}

	return user
}

func NewCas(store authenticate, host string, casAddress string, casLoginEndpoint string, casValidateEndpoint string, callbackURL func(context.Context, string) string) *cas {
	c := &cas{
		store:               store,
		casAddress:          casAddress,
		casLoginEndpoint:    casLoginEndpoint,
		casValidateEndpoint: casValidateEndpoint,
		callback:            fmt.Sprintf("%s/cas/callback", host),
		clientCallback:      callbackURL,
	}
	c.createRouter()
	return c
}

func (c *cas) createRouter() {
	c.router = mux.NewRouter()
	c.router.Path("/login").Methods("GET").HandlerFunc(c.loginRedirect)
	c.router.Path("/callback").Methods("GET").HandlerFunc(c.callbackHandler)
}

func (c *cas) loginRedirect(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("authRequestID")
	if id == "" {
		http.Error(w, fmt.Sprintf("missing authRequestID query parameter"), http.StatusNotFound)
		return
	}
	callbackQueryParams := url.Values{}
	callbackQueryParams.Set("id", id)

	queryParams := url.Values{}
	queryParams.Set("service", fmt.Sprintf("%s?%s", c.callback, callbackQueryParams.Encode()))

	http.Redirect(w, r, fmt.Sprintf("%s%s?%s", c.casAddress, c.casLoginEndpoint, queryParams.Encode()), http.StatusSeeOther)
}

func (c *cas) callbackHandler(w http.ResponseWriter, r *http.Request) {
	ticket := r.URL.Query().Get("ticket")

	id := r.FormValue("id")
	if id == "" {
		http.Error(w, "Missing id query parameter", http.StatusInternalServerError)
		return
	}

	if ticket == "" {
		http.Error(w, fmt.Sprintf("missing ticket query parameter"), http.StatusNotFound)
		return
	}

	client := &http.Client{}
	queryParams := url.Values{}
	queryParams.Set("service", c.callback)
	queryParams.Set("ticket", ticket)

	// Create a GET request with the URL
	req, err := http.NewRequest("GET", fmt.Sprintf("%s%s?%s", c.casAddress, c.casValidateEndpoint, queryParams.Encode()), nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("something went wrong while creating GET request: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	// Send the request using the client
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("something went wrong performing get request on cas validate endpoint: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("something went wrong reading the body: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	var response CasServiceResponse
	err = xml.Unmarshal(body, &response)
	if err != nil {
		http.Error(w, fmt.Sprintf("something went wrong parsing the body: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	if response.AuthenticationFailure != nil {
		http.Error(w, fmt.Sprintf("cas error: %s: %s", response.AuthenticationFailure.Code, response.AuthenticationFailure.Message), http.StatusInternalServerError)
		return
	}

	err = c.store.ValidateRequest(
		ConvertCasAuthenticationSuccessToUser(response.AuthenticationSuccess),
		id,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	callbackUrl := c.clientCallback(r.Context(), id)
	print("clientCallback: ", callbackUrl)
	http.Redirect(w, r, callbackUrl, http.StatusFound)
}
