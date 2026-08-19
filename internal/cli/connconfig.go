package cli

import "os"

// ConnConfig holds the raw DELINEA_TOOLS_* connection settings as strings: env
// values are loaded first (ConnConfigFromEnv) and flag parsing overwrites
// them. It is the ONE definition shared by the raw verbs and the secrets
// group, so the two faces of the tool cannot drift apart in which settings
// they read or how the credential is sourced. The credential lives in
// Token/Password/ClientSecret unless SecretStdin explicitly selects stdin and
// overrides those environment values.
type ConnConfig struct {
	URL, Target                   string
	Username, Password, Domain    string
	ClientID, ClientSecret, Token string
	CACert, Timeout, Retries      string
	TLSSkipVerify                 bool
	VaultAllow                    []string // --vault-allow values; any at all replace VaultAllowEnv (the flag wins)
	VaultAllowEnv                 string
	GatewayHeaderFiles            []string // --gateway-header-file values; any at all replace GatewayHeaderFileEnv
	GatewayHeaderFileEnv          string
	SecretStdin                   bool // --secret-stdin: force the credential from stdin, overriding any env/flag secret
}

// ConnConfigFromEnv loads the connection settings every face of the tool
// reads, from the one DELINEA_TOOLS_* namespace.
func ConnConfigFromEnv() ConnConfig {
	return ConnConfig{
		URL:                  os.Getenv("DELINEA_TOOLS_URL"),
		Target:               os.Getenv("DELINEA_TOOLS_TARGET"),
		Username:             os.Getenv("DELINEA_TOOLS_USERNAME"),
		Password:             os.Getenv("DELINEA_TOOLS_PASSWORD"),
		Domain:               os.Getenv("DELINEA_TOOLS_DOMAIN"),
		ClientID:             os.Getenv("DELINEA_TOOLS_CLIENT_ID"),
		ClientSecret:         os.Getenv("DELINEA_TOOLS_CLIENT_SECRET"),
		Token:                os.Getenv("DELINEA_TOOLS_TOKEN"),
		CACert:               os.Getenv("DELINEA_TOOLS_CA_CERT"),
		Timeout:              os.Getenv("DELINEA_TOOLS_TIMEOUT"),
		Retries:              os.Getenv("DELINEA_TOOLS_RETRIES"),
		TLSSkipVerify:        Truthy(os.Getenv("DELINEA_TOOLS_TLS_SKIP_VERIFY")),
		VaultAllowEnv:        os.Getenv("DELINEA_TOOLS_VAULT_ALLOW"),
		GatewayHeaderFileEnv: os.Getenv("DELINEA_TOOLS_GATEWAY_HEADER_FILE"),
	}
}

// GatewayHeaderPaths applies the ordinary flags-over-environment rule. The
// environment names one file; repeatable flags can compose several files and,
// when present, replace rather than silently widen the ambient configuration.
func (c ConnConfig) GatewayHeaderPaths() []string {
	if len(c.GatewayHeaderFiles) > 0 {
		return c.GatewayHeaderFiles
	}
	if c.GatewayHeaderFileEnv != "" {
		return []string{c.GatewayHeaderFileEnv}
	}
	return nil
}
