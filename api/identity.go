package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// maxOOBWait bounds how long oobLoop waits for an out-of-band approval before
// giving up, backstopping an unbounded caller context against a server that
// answers OobPending without end. Generous enough for a real push or emailed
// approval; a caller wanting a tighter bound sets its own context deadline.
const maxOOBWait = 5 * time.Minute

// Mechanism is one way to satisfy an Identity API authentication challenge,
// e.g. UP (password), EMAIL, SMS, OTP, OATH, PF, SQ. A Prompter matches on the
// protocol identifiers (Name, MechanismID, AnswerType) and displays the
// human-facing prompts (PromptSelectMech, PromptMechChosen).
type Mechanism struct {
	// MechanismID is the opaque protocol identifier echoed back when answering.
	MechanismID string `json:"MechanismId"`
	// Name is the mechanism kind — e.g. UP, EMAIL, SMS, OATH — a match key.
	Name string `json:"Name"`
	// AnswerType is how the mechanism is answered; a value containing "Oob"
	// marks an out-of-band challenge (an emailed link or code, or a push).
	AnswerType string `json:"AnswerType"`
	// PromptSelectMech is the human-facing label to show when offering this
	// mechanism among others.
	PromptSelectMech string `json:"PromptSelectMech"`
	// PromptMechChosen is the human-facing message to show once this mechanism
	// is chosen.
	PromptMechChosen string `json:"PromptMechChosen"`
}

// challenge is one step of an Identity API login; any one of its Mechanisms
// satisfies it.
type challenge struct {
	Mechanisms []Mechanism `json:"Mechanisms"`
}

// Prompter supplies the interactive answers InteractiveLogin cannot derive
// from configuration.
type Prompter interface {
	// ChooseMechanism picks one of mechs (always two or more) and returns
	// its index.
	ChooseMechanism(mechs []Mechanism) (int, error)
	// ReadAnswer returns the user's response to prompt, an MFA code. For an
	// out-of-band mechanism (emailed link, push), returning "" polls for
	// completion instead of answering.
	ReadAnswer(prompt string) (string, error)
}

type identityEnvelope struct {
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"Result"`
	Message string          `json:"Message"`
}

type authSession struct {
	SessionID  string      `json:"SessionId"`
	TenantID   string      `json:"TenantId"`
	Redirect   string      `json:"Redirect"`
	Challenges []challenge `json:"Challenges"`
}

type advanceResult struct {
	Summary     string      `json:"Summary"`
	Challenges  []challenge `json:"Challenges"`
	OAuthTokens struct {
		AccessToken string `json:"access_token"`
	} `json:"OAuthTokens"`
}

// InteractiveLogin authenticates cfg.Username against the platform's
// Identity API (StartAuthentication / AdvanceAuthentication) and returns the
// resulting bearer token. This is the path for MFA-gated accounts (e.g.
// cloudadmin@tenant) that the OAuth2 grants cannot serve, because those grants
// cannot answer an MFA challenge. Redirect-based federated (external IdP / SSO)
// logins are not supported: a redirect from StartAuthentication is refused
// below. The password (UP) mechanism is answered from cfg.Password; every
// other challenge is delegated to prompt. The token is returned, not cached;
// pass it as Config.Token to later clients.
func (c *Client) InteractiveLogin(ctx context.Context, prompt Prompter) (string, error) {
	if c.cfg.Username == "" || c.cfg.Password == "" {
		return "", fmt.Errorf("%w: interactive login requires Username and Password", ErrConfig)
	}
	if prompt == nil {
		return "", fmt.Errorf("%w: interactive login requires a Prompter", ErrConfig)
	}
	var sess authSession
	err := c.identityPost(ctx, "/identity/Security/StartAuthentication",
		map[string]any{"User": c.cfg.Username, "Version": "1.0"}, &sess)
	if err != nil {
		return "", err
	}
	if sess.Redirect != "" {
		return "", fmt.Errorf("%w: authentication redirected to %s; federated redirects are not supported", ErrAuth, c.authSnippet([]byte(sess.Redirect)))
	}
	if len(sess.Challenges) == 0 {
		return "", fmt.Errorf("%w: authentication offered no challenges", ErrAuth)
	}

	challenges := sess.Challenges
	passwordUsed := false
	var submittedAnswers []string
	safePrompt := &credentialRedactingPrompter{client: c, prompt: prompt, sensitive: &submittedAnswers}
	// A misbehaving or hostile endpoint can answer every step with NewPackage
	// and keep the loop cycling forever; cap the total advances so login fails
	// with a clear error instead of spinning (and re-prompting) without end.
	const maxAdvances = 32
	advances := 0
	for i := 0; i < len(challenges); i++ {
		if advances++; advances > maxAdvances {
			return "", fmt.Errorf("%w: authentication did not complete after %d challenge steps", ErrAuth, maxAdvances)
		}
		mech, err := pickMechanism(challenges[i].Mechanisms, passwordUsed, safePrompt)
		if err != nil {
			return "", err
		}
		var adv advanceResult
		switch {
		case mech.Name == "UP" && !passwordUsed:
			passwordUsed = true
			adv, err = c.advance(ctx, sess, mech, "Answer", c.cfg.Password, submittedAnswers...)
		case isOOB(mech):
			adv, err = c.oobLoop(ctx, sess, mech, safePrompt)
		default:
			ans, perr := safePrompt.ReadAnswer(answerPrompt(mech))
			if perr != nil {
				return "", perr
			}
			adv, err = c.advance(ctx, sess, mech, "Answer", ans, submittedAnswers...)
		}
		if err != nil {
			return "", err
		}
		switch adv.Summary {
		case "LoginSuccess":
			tok := adv.OAuthTokens.AccessToken
			if err := validateAccessToken(tok); err != nil {
				return "", fmt.Errorf("%w: login succeeded but %v", ErrAuth, err)
			}
			return tok, nil
		case "StartNextChallenge":
		case "NewPackage":
			if len(adv.Challenges) == 0 {
				return "", fmt.Errorf("%w: authentication sent an empty challenge package", ErrAuth)
			}
			challenges, i = adv.Challenges, -1
		default:
			sensitive := append([]string(nil), submittedAnswers...)
			sensitive = append(sensitive, adv.OAuthTokens.AccessToken)
			return "", fmt.Errorf("%w: unexpected authentication summary %q", ErrAuth, c.authSnippet([]byte(adv.Summary), sensitive...))
		}
	}
	return "", fmt.Errorf("%w: authentication completed every challenge without a token", ErrAuth)
}

// credentialRedactingPrompter keeps endpoint-controlled display strings from
// reflecting grant credentials or earlier MFA answers into an application's
// UI. The original Mechanisms remain in the login state and are used on the
// wire; only the copy supplied to the Prompter is redacted.
type credentialRedactingPrompter struct {
	client    *Client
	prompt    Prompter
	sensitive *[]string
}

func (p *credentialRedactingPrompter) ChooseMechanism(mechs []Mechanism) (int, error) {
	// One redaction pass covers every field of every mechanism (the variant
	// set is built once, not per field). Only the display strings are
	// redacted: MechanismID, Name, and AnswerType are protocol identifiers a
	// programmatic Prompter matches on (return the index whose Name is
	// "EMAIL"), and rewriting a substring of them that happens to collide
	// with a credential would corrupt that match. The prompt fields are what
	// a UI shows, so they are where a reflected credential would land.
	redact := p.client.redactText
	answers := p.answers()
	safe := append([]Mechanism(nil), mechs...)
	for i := range safe {
		safe[i].PromptSelectMech = redact(safe[i].PromptSelectMech, answers...)
		safe[i].PromptMechChosen = redact(safe[i].PromptMechChosen, answers...)
	}
	return p.prompt.ChooseMechanism(safe)
}

// ReadAnswer redacts the prompt without reshaping it: a legitimate multi-line
// or long challenge question must reach the user intact (redactText neither
// collapses whitespace nor truncates), while credentials, earlier answers,
// and terminal escape sequences still never do.
func (p *credentialRedactingPrompter) ReadAnswer(prompt string) (string, error) {
	answer, err := p.prompt.ReadAnswer(p.client.redactText(prompt, p.answers()...))
	if err == nil && answer != "" {
		*p.sensitive = append(*p.sensitive, answer)
	}
	return answer, err
}

// answers is the MFA answers submitted so far, the extra values every
// identity-path redaction includes.
func (p *credentialRedactingPrompter) answers() []string { return *p.sensitive }

// pickMechanism auto-selects the password mechanism while it is unanswered
// and any sole mechanism; only a genuine choice reaches the Prompter.
func pickMechanism(mechs []Mechanism, passwordUsed bool, prompt Prompter) (Mechanism, error) {
	if len(mechs) == 0 {
		return Mechanism{}, fmt.Errorf("%w: challenge offered no mechanisms", ErrAuth)
	}
	if !passwordUsed {
		for _, m := range mechs {
			if m.Name == "UP" {
				return m, nil
			}
		}
	}
	if len(mechs) == 1 {
		return mechs[0], nil
	}
	idx, err := prompt.ChooseMechanism(mechs)
	if err != nil {
		return Mechanism{}, err
	}
	if idx < 0 || idx >= len(mechs) {
		return Mechanism{}, fmt.Errorf("%w: mechanism choice %d out of range", ErrConfig, idx)
	}
	return mechs[idx], nil
}

func isOOB(m Mechanism) bool {
	return strings.Contains(m.AnswerType, "Oob")
}

func answerPrompt(m Mechanism) string {
	if m.PromptMechChosen != "" {
		return m.PromptMechChosen
	}
	return "Enter the " + m.Name + " code"
}

func (c *Client) oobLoop(ctx context.Context, sess authSession, mech Mechanism, prompt *credentialRedactingPrompter) (advanceResult, error) {
	adv, err := c.advance(ctx, sess, mech, "StartOOB", "", prompt.answers()...)
	// Bound the wait by elapsed time, not poll count: an out-of-band approval
	// (a push, an emailed link) legitimately takes tens of seconds, and a
	// non-interactive prompter that polls without delay would burn a fixed
	// count in a fraction of a second and fail it. A caller that sets a context
	// deadline shorter than the cap has each advance fail on it first; the cap
	// only backstops an unbounded context against a server that answers
	// OobPending without end.
	deadline := c.now().Add(maxOOBWait)
	for err == nil && adv.Summary == "OobPending" {
		if !c.now().Before(deadline) {
			return advanceResult{}, fmt.Errorf("%w: out-of-band authentication did not complete within %s", ErrAuth, maxOOBWait)
		}
		ans, perr := prompt.ReadAnswer(answerPrompt(mech) + " (empty to poll for out-of-band completion)")
		if perr != nil {
			return advanceResult{}, perr
		}
		if ans == "" {
			// Rate-limit polling to at most one request per oobPollInterval, so
			// an auto-polling prompter (empty answers) cannot hammer the Identity
			// endpoint for the whole maxOOBWait window. Honors ctx.
			if serr := sleep(ctx, c.oobPollInterval); serr != nil {
				return advanceResult{}, serr
			}
			adv, err = c.advance(ctx, sess, mech, "Poll", "", prompt.answers()...)
		} else {
			adv, err = c.advance(ctx, sess, mech, "Answer", ans, prompt.answers()...)
		}
	}
	return adv, err
}

func (c *Client) advance(ctx context.Context, sess authSession, mech Mechanism, action, answer string, sensitive ...string) (advanceResult, error) {
	body := map[string]any{
		"SessionId":   sess.SessionID,
		"TenantId":    sess.TenantID,
		"MechanismId": mech.MechanismID,
		"Action":      action,
	}
	if answer != "" {
		body["Answer"] = answer
	}
	var out advanceResult
	err := c.identityPost(ctx, "/identity/Security/AdvanceAuthentication", body, &out, sensitive...)
	return out, err
}

// identityPost sends one Identity API request; like token grants, these
// carry credentials and never follow redirects.
func (c *Client) identityPost(ctx context.Context, path string, body, out any, priorSensitive ...string) error {
	sensitive := append([]string(nil), priorSensitive...)
	if fields, ok := body.(map[string]any); ok {
		if answer, ok := fields["Answer"].(string); ok && answer != "" {
			sensitive = append(sensitive, answer)
		}
	}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConfig, err)
	}
	ictx, cancel := context.WithTimeout(context.WithValue(ctx, noRedirectsKey{}, true), c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ictx, http.MethodPost, c.base.String()+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConfig, err)
	}
	c.applyConfigHeader(req)
	setHostFromHeader(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return c.transportErrorClassifier("identity request", nil, sensitive...)(fmt.Errorf("identity request: %w", err))
	}
	defer resp.Body.Close()
	raw, oversized, err := readAuthResponse(resp.Body)
	if err != nil {
		return c.transportErrorClassifier("reading identity response", nil, sensitive...)(fmt.Errorf("reading identity response: %w", err))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// A 3xx (identity posts never follow redirects) means the URL points
		// at a front door that bounces the login — a permanent misconfig, not
		// an auth failure.
		kind := ErrAuth
		switch {
		case resp.StatusCode >= 300 && resp.StatusCode <= 399:
			kind = ErrConfig
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			kind = ErrAccessDenied
		case retriableStatus(resp.StatusCode):
			kind = ErrTransport
		}
		return fmt.Errorf("%w: identity endpoint returned %s: %s", kind, c.authSnippet([]byte(resp.Status), sensitive...), c.authSnippet(raw, sensitive...))
	}
	if oversized {
		return fmt.Errorf("%w: identity response exceeds %d bytes", ErrAuth, maxAuthResponseBytes)
	}
	var env identityEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("%w: parsing identity response: %v", ErrAuth, err)
	}
	if !env.Success {
		msg := "identity request failed"
		if env.Message != "" {
			// Server-controlled text that reaches logs and terminals: bound
			// and sanitize it like every other server body.
			msg = c.authSnippet([]byte(env.Message), sensitive...)
		}
		return fmt.Errorf("%w: %s", ErrAccessDenied, msg)
	}
	if err := json.Unmarshal(env.Result, out); err != nil {
		return fmt.Errorf("%w: parsing identity result: %v", ErrAuth, err)
	}
	return nil
}
