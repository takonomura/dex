// Code generated by ent, DO NOT EDIT.

package authrequest

const (
	// Label holds the string label denoting the authrequest type in the database.
	Label = "auth_request"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldClientID holds the string denoting the client_id field in the database.
	FieldClientID = "client_id"
	// FieldScopes holds the string denoting the scopes field in the database.
	FieldScopes = "scopes"
	// FieldResponseTypes holds the string denoting the response_types field in the database.
	FieldResponseTypes = "response_types"
	// FieldRedirectURI holds the string denoting the redirect_uri field in the database.
	FieldRedirectURI = "redirect_uri"
	// FieldNonce holds the string denoting the nonce field in the database.
	FieldNonce = "nonce"
	// FieldState holds the string denoting the state field in the database.
	FieldState = "state"
	// FieldForceApprovalPrompt holds the string denoting the force_approval_prompt field in the database.
	FieldForceApprovalPrompt = "force_approval_prompt"
	// FieldLoggedIn holds the string denoting the logged_in field in the database.
	FieldLoggedIn = "logged_in"
	// FieldClaimsUserID holds the string denoting the claims_user_id field in the database.
	FieldClaimsUserID = "claims_user_id"
	// FieldClaimsUsername holds the string denoting the claims_username field in the database.
	FieldClaimsUsername = "claims_username"
	// FieldClaimsEmail holds the string denoting the claims_email field in the database.
	FieldClaimsEmail = "claims_email"
	// FieldClaimsEmailVerified holds the string denoting the claims_email_verified field in the database.
	FieldClaimsEmailVerified = "claims_email_verified"
	// FieldClaimsGroups holds the string denoting the claims_groups field in the database.
	FieldClaimsGroups = "claims_groups"
	// FieldClaimsPreferredUsername holds the string denoting the claims_preferred_username field in the database.
	FieldClaimsPreferredUsername = "claims_preferred_username"
	// FieldConnectorID holds the string denoting the connector_id field in the database.
	FieldConnectorID = "connector_id"
	// FieldConnectorData holds the string denoting the connector_data field in the database.
	FieldConnectorData = "connector_data"
	// FieldExpiry holds the string denoting the expiry field in the database.
	FieldExpiry = "expiry"
	// FieldCodeChallenge holds the string denoting the code_challenge field in the database.
	FieldCodeChallenge = "code_challenge"
	// FieldCodeChallengeMethod holds the string denoting the code_challenge_method field in the database.
	FieldCodeChallengeMethod = "code_challenge_method"
	// FieldHmacKey holds the string denoting the hmac_key field in the database.
	FieldHmacKey = "hmac_key"
	// Table holds the table name of the authrequest in the database.
	Table = "auth_requests"
)

// Columns holds all SQL columns for authrequest fields.
var Columns = []string{
	FieldID,
	FieldClientID,
	FieldScopes,
	FieldResponseTypes,
	FieldRedirectURI,
	FieldNonce,
	FieldState,
	FieldForceApprovalPrompt,
	FieldLoggedIn,
	FieldClaimsUserID,
	FieldClaimsUsername,
	FieldClaimsEmail,
	FieldClaimsEmailVerified,
	FieldClaimsGroups,
	FieldClaimsPreferredUsername,
	FieldConnectorID,
	FieldConnectorData,
	FieldExpiry,
	FieldCodeChallenge,
	FieldCodeChallengeMethod,
	FieldHmacKey,
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}

var (
	// DefaultClaimsPreferredUsername holds the default value on creation for the "claims_preferred_username" field.
	DefaultClaimsPreferredUsername string
	// DefaultCodeChallenge holds the default value on creation for the "code_challenge" field.
	DefaultCodeChallenge string
	// DefaultCodeChallengeMethod holds the default value on creation for the "code_challenge_method" field.
	DefaultCodeChallengeMethod string
	// IDValidator is a validator for the "id" field. It is called by the builders before save.
	IDValidator func(string) error
)
