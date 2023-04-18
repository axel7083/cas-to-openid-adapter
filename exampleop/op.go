package exampleop

import (
	"crypto/sha256"
	"fmt"
	"github.com/axel7083/cas-to-openid-adapter/storage"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/zitadel/oidc/v2/pkg/op"
	"golang.org/x/text/language"
)

const (
	pathLoggedOut = "/logged-out"
)

func _init(clientID string, clientSecret string, prefixUrl string, clientRedirectUri string) {
	storage.RegisterClients(
		storage.WebClient(clientID, clientSecret, prefixUrl, clientRedirectUri),
	)
}

type Storage interface {
	op.Storage
	authenticate
}

// SetupServer creates an OIDC server with Issuer=http://localhost:<port>
//
// Use one of the pre-made clients in storage/clients.go or register a new one.
func SetupServer(opts Options, storage Storage) *mux.Router {
	// init the client
	_init(opts.ClientID, opts.ClientSecret, opts.PrefixURL, opts.ClientRedirectURI)

	if !strings.HasSuffix(opts.Issuer, opts.PrefixURL) {
		log.Fatalf("when a prefixURL is used, the issuer must end with it.")
	}

	// the OpenID Provider requires a 32-byte keys for (token) encryption
	// be sure to create a proper crypto random keys and manage it securely!
	key := sha256.Sum256([]byte(opts.OpenIDKeyPhrase))

	router := mux.NewRouter()

	// for simplicity, we provide a very small default page for users who have signed out
	router.HandleFunc(pathLoggedOut, func(w http.ResponseWriter, req *http.Request) {
		_, err := w.Write([]byte("signed out successfully"))
		if err != nil {
			log.Printf("error serving logged out page: %v", err)
		}
	})

	// creation of the OpenIDProvider with the just created in-memory Storage
	provider, err := newOP(storage, opts.Issuer, key)
	if err != nil {
		log.Fatal(err)
	}

	u, err := url.Parse(opts.Issuer)
	if err != nil {
		log.Fatalf("the issuer url could not be parsed: %s", err.Error())
	}

	var externalGroupsProvider *ExternalGroupsProvider = nil
	if opts.ExternalGroupsProvider != "" {
		externalGroupsProvider = NewExternalGroupsProvider(opts.ExternalGroupsProvider, opts.EgpHeader)
	}

	u.Path = ""
	u.RawQuery = ""

	// the provider will only take care of the OpenID Protocol, so there must be some sort of UI for the login process
	// for the simplicity of the example this means a simple page with username and password field
	c := NewCas(
		storage,
		u.String(),
		opts.PrefixURL,
		opts.CasAddress,
		opts.CasLoginEndpoint,
		opts.CasLogoutEndpoint,
		opts.CasValidateEndpoint,
		op.AuthCallbackURL(provider),
		externalGroupsProvider,
	)

	router.PathPrefix(opts.PrefixURL + "/cas/").Handler(http.StripPrefix(opts.PrefixURL+"/cas", c.router))
	router.PathPrefix(opts.PrefixURL).Handler(http.StripPrefix(opts.PrefixURL, provider.HttpHandler()))

	router.NotFoundHandler = customNotFoundHandler()

	return router
}

func customNotFoundHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("handling 404")
		// Get the requested URI from the request object
		uri := r.URL.RequestURI()

		// Set the response status code to 404 Not Found
		w.WriteHeader(http.StatusNotFound)

		// Write the URI to the response body
		fmt.Fprintf(w, "404: Page not found - %s", uri)
	})
}

// newOP will create an OpenID Provider for localhost on a specified port with a given encryption keys
// and a predefined default logout uri
// it will enable all options (see descriptions)
func newOP(storage op.Storage, issuer string, key [32]byte) (op.OpenIDProvider, error) {
	config := &op.Config{
		CryptoKey: key,

		// will be used if the end_session endpoint is called without a post_logout_redirect_uri
		DefaultLogoutRedirectURI: pathLoggedOut,

		// enables code_challenge_method S256 for PKCE (and therefore PKCE in general)
		CodeMethodS256: true,

		// enables additional client_id/client_secret authentication by form post (not only HTTP Basic Auth)
		AuthMethodPost: false,

		// enables additional authentication by using private_key_jwt
		AuthMethodPrivateKeyJWT: false,

		// enables refresh_token grant use
		GrantTypeRefreshToken: true,

		// enables use of the `request` Object parameter
		RequestObjectSupported: false,

		// this example has only static texts (in English), so we'll set the here accordingly
		SupportedUILocales: []language.Tag{language.English},

		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     5 * time.Minute,
			PollInterval: 5 * time.Second,
			UserFormURL:  issuer + "device",
			UserCode:     op.UserCodeBase20,
		},
	}
	handler, err := op.NewOpenIDProvider(issuer, config, storage,
		//we must explicitly allow the use of the http issuer
		op.WithAllowInsecure(),
		// as an example on how to customize an endpoint this will change the authorization_endpoint from /authorize to /auth
		op.WithCustomAuthEndpoint(op.NewEndpoint("auth")),
	)

	if err != nil {
		return nil, err
	}
	return handler, nil
}
