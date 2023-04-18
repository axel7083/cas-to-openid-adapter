package exampleop

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type ExternalGroupsProvider struct {
	url    string // URL address of the external groups provider
	header string // Header identifier to be included in the request
}

// NewExternalGroupsProvider Constructor function for ExternalGroupsProvider
func NewExternalGroupsProvider(url string, header string) *ExternalGroupsProvider {
	return &ExternalGroupsProvider{url, header}
}

// GetGroups function retrieves the groups associated with a given user ID from the external provider.
func (egp *ExternalGroupsProvider) GetGroups(userID string) ([]string, error) {
	// Create a new HTTP request with the URL address of the external groups provider.
	req, err := http.NewRequest("GET", egp.url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Add the header identifier and user ID to the request header.
	req.Header.Set(egp.header, userID)

	// Send the HTTP request and get the response.
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Decode the JSON response into an array of strings.
	var groups []string
	err = json.NewDecoder(resp.Body).Decode(&groups)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	// Return the retrieved groups.
	return groups, nil
}
