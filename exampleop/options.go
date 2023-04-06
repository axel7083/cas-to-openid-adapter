package exampleop

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
)

type Options struct {
	Host                string `env:"HOST" default:"localhost"`
	Port                string `env:"PORT" default:"9998"`
	PrefixURL           string `env:"PREFIX_URL" default:""`
	Issuer              string `env:"ISSUER" default:"http://localhost:9998/"`
	CasAddress          string `env:"CAS_ADDRESS"`
	CasLoginEndpoint    string `env:"CAS_LOGIN_ENDPOINT" default:"/login"`
	CasLogoutEndpoint   string `env:"CAS_LOGOUT_ENDPOINT" default:"/logout"`
	CasValidateEndpoint string `env:"CAS_VALIDATE_ENDPOINT" default:"/serviceValidate"`
	ClientID            string `env:"CLIENT_ID" default:"web"`
	ClientSecret        string `env:"CLIENT_SECRET"`
	ClientRedirectURI   string `env:"CLIENT_REDIRECT_URI" default:"http://localhost:9999/auth/callback"`
	OpenIDKeyPhrase     string `env:"OPENID_KEY_PHRASE"`
	SigningPrivateKey   string `env:"SIGNING_PRIVATE_KEY"`
	SigningPublicKey    string `env:"SIGNING_PUBLIC_KEY"`
	SigningKeyID        string `env:"SIGNING_KEY_ID" default:"682a39b4-cf9f-40de-9fdd-b5c78ff07fe4"`
}

// getOptionsFromEnv retrieves options for a service from environment variables.
// The function returns an Options struct and an error if any required variables are missing.
func ParseOptionsFromEnv(opts interface{}) error {
	val := reflect.ValueOf(opts).Elem()
	typ := val.Type()

	for i := 0; i < typ.NumField(); i++ {
		field := val.Field(i)
		tag := typ.Field(i).Tag.Get("env")
		if tag == "" {
			return fmt.Errorf("missing env tag for field: %s", typ.Field(i).Name)
		}

		value, ok := os.LookupEnv(tag)
		if !ok {
			defaultVal, exist := typ.Field(i).Tag.Lookup("default")
			if !exist {
				return fmt.Errorf("missing required env variable: %s", tag)
			} else {
				value = defaultVal
			}
		}

		switch field.Kind() {
		case reflect.String:
			field.SetString(value)
		case reflect.Int:
			intVal, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid value for env variable %s: %s", tag, value)
			}
			field.SetInt(int64(intVal))
		default:
			return fmt.Errorf("unsupported field type: %v", field.Kind())
		}
	}

	return nil
}
