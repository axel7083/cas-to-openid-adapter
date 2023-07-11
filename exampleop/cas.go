package exampleop

import (
	"context"
	"encoding/xml"
	"fmt"
	"github.com/axel7083/cas-to-openid-adapter/storage"
	"github.com/gorilla/mux"
	"golang.org/x/text/language"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type authenticate interface {
	ValidateRequest(user *storage.User, id string) error
}

type Cas struct {
	store                  authenticate
	prefixURL              string
	casAddress             string
	casLoginEndpoint       string
	casLogoutEndpoint      string
	casValidateEndpoint    string
	router                 *mux.Router
	callback               string
	logoutCallback         string
	clientCallback         func(context.Context, string) string
	externalGroupsProvider *ExternalGroupsProvider
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

func NewCas(
	store authenticate,
	host string,
	prefixURL string,
	casAddress string,
	casLoginEndpoint string,
	casLogoutEndpoint string,
	casValidateEndpoint string,
	callbackURL func(context.Context, string) string,
	externalGroupsProvider *ExternalGroupsProvider,
) *Cas {
	c := &Cas{
		store:                  store,
		prefixURL:              prefixURL,
		casAddress:             casAddress,
		casLoginEndpoint:       casLoginEndpoint,
		casLogoutEndpoint:      casLogoutEndpoint,
		casValidateEndpoint:    casValidateEndpoint,
		callback:               fmt.Sprintf("%s%s/cas/callback", host, prefixURL),
		logoutCallback:         host,
		clientCallback:         callbackURL,
		externalGroupsProvider: externalGroupsProvider,
	}
	c.createRouter()
	return c
}

func (c *Cas) createRouter() {
	c.router = mux.NewRouter()
	c.router.Path("/login").Methods("GET").HandlerFunc(c.loginRedirect)
	c.router.Path("/logout").Methods("GET").HandlerFunc(c.logoutHandler)
	c.router.Path("/callback").Methods("GET").HandlerFunc(c.callbackHandler)
}

func (c *Cas) generateCasLoginURL(id string, redirectCount int) string {
	callbackQueryParams := url.Values{}
	callbackQueryParams.Set("id", id)
	callbackQueryParams.Set("c", strconv.Itoa(redirectCount))

	queryParams := url.Values{}
	queryParams.Set("service", fmt.Sprintf("%s?%s", c.callback, callbackQueryParams.Encode()))
	return fmt.Sprintf("%s%s?%s", c.casAddress, c.casLoginEndpoint, queryParams.Encode())
}

func (c *Cas) loginRedirect(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("authRequestID")
	if id == "" {
		http.Error(w, fmt.Sprintf("missing authRequestID query parameter"), http.StatusNotFound)
		return
	}
	log.Printf("[cas] redirect to cas provider")
	http.Redirect(w, r, c.generateCasLoginURL(id, 0), http.StatusSeeOther)
}

func (c *Cas) logoutHandler(w http.ResponseWriter, r *http.Request) {
	queryParams := url.Values{}
	queryParams.Set("service", c.logoutCallback)
	logoutCasUrl := fmt.Sprintf("%s%s?%s", c.casAddress, c.casLogoutEndpoint, queryParams.Encode())

	log.Printf("[cas] logoutHandler - %s", logoutCasUrl)

	http.Redirect(w, r, logoutCasUrl, http.StatusSeeOther)
}

func (c *Cas) callbackHandler(w http.ResponseWriter, r *http.Request) {
	ticket := r.URL.Query().Get("ticket")

	id := r.FormValue("id")
	if id == "" {
		http.Error(w, "Missing id query parameter", http.StatusInternalServerError)
		return
	}

	// Sometimes a cas provider will redirect the user without a ticket, we just need to send the user back.
	// We prevent an infinity redirect by adding the "c" query parameter in the callback.
	if ticket == "" {
		log.Printf("[cas] callback handler called without a ticket in query parameter.")
		redirectCount := r.FormValue("c")
		if redirectCount == "" {
			http.Error(w, fmt.Sprintf("missing ticket and redirectCount query parameter"), http.StatusNotFound)
			return
		}

		v, ok := strconv.Atoi(redirectCount)
		if ok != nil {
			http.Error(w, fmt.Sprintf("malformed redirect count query parameter (c)."), http.StatusNotFound)
			return
		}

		if v > 2 {
			http.Error(w, fmt.Sprintf("too many redirect, the cas provider has never provided a ticket. Please logout and retry."), http.StatusNotFound)
		} else {
			http.Redirect(w, r, c.generateCasLoginURL(id, 0), http.StatusSeeOther)
		}
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

	user := ConvertCasAuthenticationSuccessToUser(response.AuthenticationSuccess)

	// Since the cas protocol is not providing the groups
	// we allow external provider to provide them
	// This is not really secure
	if c.externalGroupsProvider != nil {
		groups, err := c.externalGroupsProvider.GetGroups(user.Email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		user.Groups = groups
	}

	err = c.store.ValidateRequest(
		user,
		id,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	callbackUrl := c.clientCallback(r.Context(), id)

	if !strings.HasPrefix(callbackUrl, "http") && !strings.HasPrefix(callbackUrl, c.prefixURL) {
		log.Printf("The callback url %s does not have the issuer in prefix, and does not have the prefixURL also. Therefore adding it (%s).", callbackUrl, c.prefixURL)
		callbackUrl = c.prefixURL + callbackUrl
	}

	http.Redirect(w, r, callbackUrl, http.StatusFound)
}
