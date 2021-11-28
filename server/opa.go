package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/dexidp/dex/connector"
)

type (
	opaInputConnector struct {
		ID string `json:"id"`
	}
	opaIdentity struct {
		UserID            *string   `json:"user_id"`
		Username          *string   `json:"username"`
		PreferredUsername *string   `json:"preferred_username"`
		Email             *string   `json:"email"`
		EmailVerified     *bool     `json:"email_verified"`
		Groups            *[]string `json:"groups"`
	}
	opaInput struct {
		Connector opaInputConnector `json:"connector"`
		Identity  opaIdentity       `json:"identity"`
	}
	opaResult struct {
		Deny             []string    `json:"deny"`
		OverrideIdentity opaIdentity `json:"override_identity"`
	}
)

func (s *Server) opaEvalPolicy(connectorID string, identity connector.Identity) (connector.Identity, error) {
	if s.opaPolicyURL == "" {
		return identity, nil
	}

	reqBody := struct {
		Input opaInput `json:"input"`
	}{
		Input: opaInput{
			Connector: opaInputConnector{
				ID: connectorID,
			},
			Identity: opaIdentity{
				UserID:            &identity.UserID,
				Username:          &identity.Username,
				PreferredUsername: &identity.PreferredUsername,
				Email:             &identity.Email,
				EmailVerified:     &identity.EmailVerified,
				Groups:            &identity.Groups,
			},
		},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return connector.Identity{}, fmt.Errorf("marshaling request: %v", err)
	}

	req, err := http.NewRequest("POST", s.opaPolicyURL, bytes.NewReader(body))
	if err != nil {
		return connector.Identity{}, fmt.Errorf("creating request: %v", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Content-Length", strconv.Itoa(len(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return connector.Identity{}, fmt.Errorf("requesting: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return connector.Identity{}, fmt.Errorf("server returned error: %d %s", resp.StatusCode, resp.Status)
	}

	var res struct {
		Result opaResult `json:"result"`
	}
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return connector.Identity{}, fmt.Errorf("unmarshaling response: %v", err)
	}

	if len(res.Result.Deny) > 0 {
		return connector.Identity{}, errors.New(strings.Join(res.Result.Deny, "\n"))
	}

	if res.Result.OverrideIdentity.UserID != nil {
		identity.UserID = *res.Result.OverrideIdentity.UserID
	}
	if res.Result.OverrideIdentity.Username != nil {
		identity.Username = *res.Result.OverrideIdentity.Username
	}
	if res.Result.OverrideIdentity.PreferredUsername != nil {
		identity.PreferredUsername = *res.Result.OverrideIdentity.PreferredUsername
	}
	if res.Result.OverrideIdentity.Email != nil {
		identity.Email = *res.Result.OverrideIdentity.Email
	}
	if res.Result.OverrideIdentity.EmailVerified != nil {
		identity.EmailVerified = *res.Result.OverrideIdentity.EmailVerified
	}
	if res.Result.OverrideIdentity.Groups != nil {
		identity.Groups = *res.Result.OverrideIdentity.Groups
	}

	return identity, nil
}
