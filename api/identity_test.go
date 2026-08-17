package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type scriptPrompter struct {
	choices    []int
	answers    []string
	prompts    []string
	mechanisms [][]Mechanism
}

func (p *scriptPrompter) ChooseMechanism(mechs []Mechanism) (int, error) {
	p.mechanisms = append(p.mechanisms, append([]Mechanism(nil), mechs...))
	if len(p.choices) == 0 {
		return 0, errors.New("unexpected ChooseMechanism call")
	}
	c := p.choices[0]
	p.choices = p.choices[1:]
	return c, nil
}

func (p *scriptPrompter) ReadAnswer(prompt string) (string, error) {
	p.prompts = append(p.prompts, prompt)
	if len(p.answers) == 0 {
		return "", errors.New("unexpected ReadAnswer call")
	}
	a := p.answers[0]
	p.answers = p.answers[1:]
	return a, nil
}

// alwaysPollPrompter answers every out-of-band prompt with "" (poll), never
// supplying a code — the shape that would spin an uncapped oobLoop forever.
type alwaysPollPrompter struct{}

func (alwaysPollPrompter) ChooseMechanism([]Mechanism) (int, error) { return 0, nil }
func (alwaysPollPrompter) ReadAnswer(string) (string, error)        { return "", nil }

type advanceReq struct {
	SessionID   string `json:"SessionId"`
	TenantID    string `json:"TenantId"`
	MechanismID string `json:"MechanismId"`
	Action      string `json:"Action"`
	Answer      string `json:"Answer"`
}

func identityServer(t *testing.T, startResult string, advance func(t *testing.T, req advanceReq) string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/Security/StartAuthentication":
			fmt.Fprintf(w, `{"success":true,"Result":%s}`, startResult)
		case "/identity/Security/AdvanceAuthentication":
			var req advanceReq
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decoding advance request: %v", err)
			}
			if req.SessionID != "s1" || req.TenantID != "t1" {
				t.Errorf("advance session: got %q/%q, want s1/t1", req.SessionID, req.TenantID)
			}
			fmt.Fprint(w, advance(t, req))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

const startUPOnly = `{"SessionId":"s1","TenantId":"t1","Challenges":[
	{"Mechanisms":[{"MechanismId":"m-up","Name":"UP","AnswerType":"Text","PromptMechChosen":"Enter Password"}]}]}`

const startUPThenEmail = `{"SessionId":"s1","TenantId":"t1","Challenges":[
	{"Mechanisms":[{"MechanismId":"m-up","Name":"UP","AnswerType":"Text"}]},
	{"Mechanisms":[{"MechanismId":"m-email","Name":"EMAIL","AnswerType":"StartTextOob","PromptMechChosen":"Enter the emailed code"}]}]}`

func loginClient(t *testing.T, url string) *Client {
	t.Helper()
	c, err := New(Config{URL: url, Username: "cloudadmin@t", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	c.oobPollInterval = 0 // poll without real delay in tests
	return c
}

func TestInteractiveLoginPasswordOnly(t *testing.T) {
	srv := identityServer(t, startUPOnly, func(t *testing.T, req advanceReq) string {
		if req.MechanismID != "m-up" || req.Action != "Answer" || req.Answer != "pw" {
			t.Errorf("unexpected advance: %+v", req)
		}
		return `{"success":true,"Result":{"Summary":"LoginSuccess","OAuthTokens":{"access_token":"tok-interactive"}}}`
	})
	p := &scriptPrompter{}
	tok, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok-interactive" {
		t.Errorf("token: got %q", tok)
	}
	if len(p.prompts) != 0 {
		t.Errorf("prompter should not have been consulted: %v", p.prompts)
	}
}

// Interactive login must be constructible and runnable with an explicit
// Target: platform - the natural configuration for a Platform login (and what
// the CLI sets). Before, New rejected platform+username/password because it
// enforced the automatic client-credentials rule on the interactive path.
func TestInteractiveLoginExplicitPlatformTarget(t *testing.T) {
	srv := identityServer(t, startUPOnly, func(t *testing.T, req advanceReq) string {
		return `{"success":true,"Result":{"Summary":"LoginSuccess","OAuthTokens":{"access_token":"tok-interactive"}}}`
	})
	c, err := New(Config{URL: srv.URL, Target: TargetPlatform, Username: "cloudadmin@t", Password: "pw"})
	if err != nil {
		t.Fatalf("New with Target platform and username/password: %v", err)
	}
	tok, err := c.InteractiveLogin(context.Background(), &scriptPrompter{})
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok-interactive" {
		t.Errorf("token: got %q", tok)
	}
}

// A token carrying control characters (a hostile Identity endpoint) is rejected
// rather than returned to be placed in a header or printed.
func TestInteractiveLoginRejectsMalformedToken(t *testing.T) {
	srv := identityServer(t, startUPOnly, func(t *testing.T, req advanceReq) string {
		return `{"success":true,"Result":{"Summary":"LoginSuccess","OAuthTokens":{"access_token":"tok\tbad"}}}`
	})
	_, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), &scriptPrompter{})
	if err == nil || !errors.Is(err, ErrAuth) {
		t.Errorf("got %v, want an ErrAuth rejection of the malformed token", err)
	}
}

func TestInteractiveLoginRejectsShortToken(t *testing.T) {
	srv := identityServer(t, startUPOnly, func(t *testing.T, req advanceReq) string {
		return `{"success":true,"Result":{"Summary":"LoginSuccess","OAuthTokens":{"access_token":"abc"}}}`
	})
	_, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), &scriptPrompter{})
	if !errors.Is(err, ErrAuth) {
		t.Errorf("got %v, want an ErrAuth rejection of the short token", err)
	}
}

func TestInteractiveLoginEmailOOB(t *testing.T) {
	var actions []string
	srv := identityServer(t, startUPThenEmail, func(t *testing.T, req advanceReq) string {
		actions = append(actions, req.MechanismID+":"+req.Action)
		switch {
		case req.MechanismID == "m-up" && req.Action == "Answer":
			return `{"success":true,"Result":{"Summary":"StartNextChallenge"}}`
		case req.MechanismID == "m-email" && req.Action == "StartOOB":
			return `{"success":true,"Result":{"Summary":"OobPending"}}`
		case req.MechanismID == "m-email" && req.Action == "Poll":
			return `{"success":true,"Result":{"Summary":"OobPending"}}`
		case req.MechanismID == "m-email" && req.Action == "Answer" && req.Answer == "12345678":
			return `{"success":true,"Result":{"Summary":"LoginSuccess","OAuthTokens":{"access_token":"tok-mfa"}}}`
		}
		t.Errorf("unexpected advance: %+v", req)
		return `{"success":false,"Message":"bad"}`
	})
	p := &scriptPrompter{answers: []string{"", "12345678"}}
	tok, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok-mfa" {
		t.Errorf("token: got %q", tok)
	}
	want := []string{"m-up:Answer", "m-email:StartOOB", "m-email:Poll", "m-email:Answer"}
	if fmt.Sprint(actions) != fmt.Sprint(want) {
		t.Errorf("actions: got %v, want %v", actions, want)
	}
}

func TestInteractiveLoginMechanismChoice(t *testing.T) {
	start := `{"SessionId":"s1","TenantId":"t1","Challenges":[
		{"Mechanisms":[{"MechanismId":"m-up","Name":"UP","AnswerType":"Text"}]},
		{"Mechanisms":[
			{"MechanismId":"m-email","Name":"EMAIL","AnswerType":"StartTextOob"},
			{"MechanismId":"m-otp","Name":"OTP","AnswerType":"Text"}]}]}`
	srv := identityServer(t, start, func(t *testing.T, req advanceReq) string {
		switch {
		case req.MechanismID == "m-up":
			return `{"success":true,"Result":{"Summary":"StartNextChallenge"}}`
		case req.MechanismID == "m-otp" && req.Action == "Answer" && req.Answer == "000111":
			return `{"success":true,"Result":{"Summary":"LoginSuccess","OAuthTokens":{"access_token":"tok-otp"}}}`
		}
		t.Errorf("unexpected advance: %+v", req)
		return `{"success":false,"Message":"bad"}`
	})
	p := &scriptPrompter{choices: []int{1}, answers: []string{"000111"}}
	tok, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok-otp" {
		t.Errorf("token: got %q", tok)
	}
}

// An out-of-band approval that takes many polls to arrive still succeeds: the
// wait is bounded by time, not a poll count, so a fast non-interactive poller
// does not exhaust a fixed budget before the user approves.
func TestInteractiveLoginOOBManyPollsSucceed(t *testing.T) {
	var polls int
	srv := identityServer(t, startUPThenEmail, func(t *testing.T, req advanceReq) string {
		switch {
		case req.MechanismID == "m-up" && req.Action == "Answer":
			return `{"success":true,"Result":{"Summary":"StartNextChallenge"}}`
		case req.MechanismID == "m-email" && req.Action == "StartOOB":
			return `{"success":true,"Result":{"Summary":"OobPending"}}`
		case req.MechanismID == "m-email" && req.Action == "Poll":
			polls++
			if polls < 50 { // far past the old count cap of 32
				return `{"success":true,"Result":{"Summary":"OobPending"}}`
			}
			return `{"success":true,"Result":{"Summary":"LoginSuccess","OAuthTokens":{"access_token":"tok-oob"}}}`
		}
		t.Errorf("unexpected advance: %+v", req)
		return `{"success":false,"Message":"bad"}`
	})
	c := loginClient(t, srv.URL)
	c.now = func() time.Time { return time.Unix(0, 0) } // clock does not advance; only poll count grows
	tok, err := c.InteractiveLogin(context.Background(), &alwaysPollPrompter{})
	if err != nil {
		t.Fatalf("login after %d polls: %v", polls, err)
	}
	if tok != "tok-oob" {
		t.Errorf("token: got %q, want tok-oob", tok)
	}
	if polls < 50 {
		t.Errorf("polls: got %d, want >= 50 (the count cap is gone)", polls)
	}
}

// A server that answers every out-of-band poll with OobPending does not spin
// forever: once maxOOBWait elapses, login fails with a clear error even when
// the caller's context has no deadline.
func TestInteractiveLoginOOBTimeCap(t *testing.T) {
	srv := identityServer(t, startUPThenEmail, func(t *testing.T, req advanceReq) string {
		switch {
		case req.MechanismID == "m-up" && req.Action == "Answer":
			return `{"success":true,"Result":{"Summary":"StartNextChallenge"}}`
		case req.MechanismID == "m-email" && (req.Action == "StartOOB" || req.Action == "Poll"):
			return `{"success":true,"Result":{"Summary":"OobPending"}}`
		}
		t.Errorf("unexpected advance: %+v", req)
		return `{"success":false,"Message":"bad"}`
	})
	c := loginClient(t, srv.URL)
	base := time.Unix(0, 0)
	var calls int
	c.now = func() time.Time { calls++; return base.Add(time.Duration(calls) * time.Minute) } // advances 1m per call
	_, err := c.InteractiveLogin(context.Background(), &alwaysPollPrompter{})
	if !errors.Is(err, ErrAuth) {
		t.Errorf("err: got %v, want ErrAuth after maxOOBWait", err)
	}
}

func TestInteractiveLoginNewPackage(t *testing.T) {
	srv := identityServer(t, startUPOnly, func(t *testing.T, req advanceReq) string {
		switch {
		case req.MechanismID == "m-up":
			return `{"success":true,"Result":{"Summary":"NewPackage","Challenges":[
				{"Mechanisms":[{"MechanismId":"m-otp","Name":"OTP","AnswerType":"Text"}]}]}}`
		case req.MechanismID == "m-otp" && req.Answer == "222333":
			return `{"success":true,"Result":{"Summary":"LoginSuccess","OAuthTokens":{"access_token":"tok-pkg"}}}`
		}
		t.Errorf("unexpected advance: %+v", req)
		return `{"success":false,"Message":"bad"}`
	})
	p := &scriptPrompter{answers: []string{"222333"}}
	tok, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok-pkg" {
		t.Errorf("token: got %q", tok)
	}
}

func TestInteractiveLoginWrongPassword(t *testing.T) {
	srv := identityServer(t, startUPOnly, func(t *testing.T, req advanceReq) string {
		return `{"success":false,"Message":"Login failed."}`
	})
	_, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), &scriptPrompter{})
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("got %v, want errors.Is ErrAccessDenied", err)
	}
}

func TestInteractiveLoginRedactsReflectedPassword(t *testing.T) {
	srv := identityServer(t, startUPOnly, func(t *testing.T, req advanceReq) string {
		return `{"success":false,"Message":"rejected pw"}`
	})
	_, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), &scriptPrompter{})
	if err == nil || strings.Contains(err.Error(), "rejected pw") || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("password reflection was not redacted: %v", err)
	}
}

func TestInteractiveLoginTransientStatusIsTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, "temporarily unavailable")
	}))
	defer srv.Close()
	_, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), &scriptPrompter{})
	if !errors.Is(err, ErrTransport) || errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want only ErrTransport", err)
	}
}

func TestInteractiveLoginRejectsOversizedResponse(t *testing.T) {
	prefix := `{"success":true,"Result":` + startUPOnly + `}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, prefix)
		fmt.Fprint(w, strings.Repeat(" ", maxAuthResponseBytes-len(prefix)))
		fmt.Fprint(w, "x")
	}))
	defer srv.Close()
	_, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), &scriptPrompter{})
	if !errors.Is(err, ErrAuth) || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("got %v, want an ErrAuth size error", err)
	}
}

func TestInteractiveLoginSanitizesServerMessage(t *testing.T) {
	srv := identityServer(t, startUPOnly, func(t *testing.T, req advanceReq) string {
		return `{"success":false,"Message":"denied\u001b[31m ` + strings.Repeat("x", 500) + `"}`
	})
	_, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), &scriptPrompter{})
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("got %v, want errors.Is ErrAccessDenied", err)
	}
	if strings.ContainsRune(err.Error(), '\x1b') {
		t.Errorf("error carries a raw escape byte from the server: %q", err.Error())
	}
	if len(err.Error()) > 300 {
		t.Errorf("error is %d bytes; the server message must be bounded", len(err.Error()))
	}
}

func TestInteractiveLoginErrors(t *testing.T) {
	cases := []struct {
		name        string
		startResult string
		want        error
	}{
		{"redirect", `{"SessionId":"s1","TenantId":"t1","Redirect":"https://idp.example.com"}`, ErrAuth},
		{"no challenges", `{"SessionId":"s1","TenantId":"t1","Challenges":[]}`, ErrAuth},
	}
	for _, tc := range cases {
		srv := identityServer(t, tc.startResult, func(t *testing.T, req advanceReq) string {
			t.Errorf("%s: advance should not be reached", tc.name)
			return `{"success":false}`
		})
		_, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), &scriptPrompter{})
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want errors.Is %v", tc.name, err, tc.want)
		}
	}
}

func TestInteractiveLoginRequiresCredentials(t *testing.T) {
	c, err := New(Config{URL: "https://x.example.com", Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.InteractiveLogin(context.Background(), &scriptPrompter{})
	if !errors.Is(err, ErrConfig) {
		t.Errorf("got %v, want errors.Is ErrConfig", err)
	}
}

func TestInteractiveLoginRequiresPrompter(t *testing.T) {
	c, err := New(Config{URL: "https://x.example.com", Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.InteractiveLogin(context.Background(), nil); !errors.Is(err, ErrConfig) {
		t.Fatalf("got %v, want ErrConfig instead of a panic", err)
	}
}

func TestInteractiveLoginSanitizesRedirect(t *testing.T) {
	start := `{"SessionId":"s1","TenantId":"t1","Redirect":"https://idp.example.com/pw\u001b[31m"}`
	srv := identityServer(t, start, func(t *testing.T, req advanceReq) string {
		t.Fatal("advance should not be reached")
		return ""
	})
	_, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), &scriptPrompter{})
	if err == nil || strings.ContainsRune(err.Error(), '\x1b') || strings.Contains(err.Error(), "/pw") || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("redirect was not safely rendered: %v", err)
	}
}

func TestInteractiveLoginUnexpectedSummary(t *testing.T) {
	srv := identityServer(t, startUPOnly, func(t *testing.T, req advanceReq) string {
		return `{"success":true,"Result":{"Summary":"SomethingElse"}}`
	})
	_, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), &scriptPrompter{})
	if !errors.Is(err, ErrAuth) {
		t.Errorf("got %v, want errors.Is ErrAuth", err)
	}
}

func TestInteractiveLoginRedactsTokenInUnexpectedSummary(t *testing.T) {
	const token = "unexpected-summary-token"
	srv := identityServer(t, startUPOnly, func(t *testing.T, req advanceReq) string {
		return `{"success":true,"Result":{"Summary":"` + token + `","OAuthTokens":{"access_token":"` + token + `"}}}`
	})
	_, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), &scriptPrompter{})
	if err == nil || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("token reflection was not redacted: %v", err)
	}
}

func TestInteractiveLoginRedactsAnswerInSuccessfulSummary(t *testing.T) {
	const answer = "654321MFA"
	start := `{"SessionId":"s1","TenantId":"t1","Challenges":[
		{"Mechanisms":[{"MechanismId":"m-otp","Name":"OTP","AnswerType":"Text"}]}]}`
	srv := identityServer(t, start, func(t *testing.T, req advanceReq) string {
		if req.Answer != answer {
			t.Errorf("answer = %q, want %q", req.Answer, answer)
		}
		return `{"success":true,"Result":{"Summary":"` + answer + `"}}`
	})
	p := &scriptPrompter{answers: []string{answer}}
	_, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), p)
	if err == nil || strings.Contains(err.Error(), answer) || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("MFA answer reflection was not redacted: %v", err)
	}
}

func TestInteractiveLoginRedactsAnswerInLaterChallengePrompt(t *testing.T) {
	const firstAnswer = "654321MFA"
	start := `{"SessionId":"s1","TenantId":"t1","Challenges":[
		{"Mechanisms":[{"MechanismId":"m-first","Name":"OTP","AnswerType":"Text"}]}]}`
	srv := identityServer(t, start, func(t *testing.T, req advanceReq) string {
		switch req.MechanismID {
		case "m-first":
			return `{"success":true,"Result":{"Summary":"NewPackage","Challenges":[
				{"Mechanisms":[{"MechanismId":"m-second","Name":"OTP","AnswerType":"Text","PromptMechChosen":"Do not repeat ` + firstAnswer + `"}]}]}}`
		case "m-second":
			return `{"success":true,"Result":{"Summary":"LoginSuccess","OAuthTokens":{"access_token":"tok-redacted-prompt"}}}`
		default:
			t.Fatalf("unexpected mechanism %q", req.MechanismID)
			return ""
		}
	})
	p := &scriptPrompter{answers: []string{firstAnswer, "second-answer"}}
	tok, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok-redacted-prompt" {
		t.Errorf("token = %q", tok)
	}
	if len(p.prompts) != 2 || strings.Contains(p.prompts[1], firstAnswer) || !strings.Contains(p.prompts[1], "[REDACTED]") {
		t.Fatalf("later challenge prompt was not redacted: %v", p.prompts)
	}
}

func TestInteractiveLoginRedactsMechanismChoiceFields(t *testing.T) {
	const password = "PASSWORDSECRET"
	start := `{"SessionId":"s1","TenantId":"t1","Challenges":[{"Mechanisms":[
		{"MechanismId":"m-one","Name":"OTP","AnswerType":"Text","PromptSelectMech":"` + password + `","PromptMechChosen":""},
		{"MechanismId":"m-two","Name":"EMAIL","AnswerType":"Text"}]}]}`
	srv := identityServer(t, start, func(t *testing.T, req advanceReq) string {
		if req.MechanismID != "m-one" {
			t.Errorf("mechanism = %q, want original m-one", req.MechanismID)
		}
		return `{"success":true,"Result":{"Summary":"LoginSuccess","OAuthTokens":{"access_token":"tok-choice"}}}`
	})
	c, err := New(Config{URL: srv.URL, Username: "cloudadmin@t", Password: password})
	if err != nil {
		t.Fatal(err)
	}
	p := &scriptPrompter{choices: []int{0}, answers: []string{"123456"}}
	if _, err := c.InteractiveLogin(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if len(p.mechanisms) != 1 || len(p.mechanisms[0]) != 2 {
		t.Fatalf("mechanism choices = %v", p.mechanisms)
	}
	got := p.mechanisms[0][0]
	if strings.Contains(got.PromptSelectMech, password) || !strings.Contains(got.PromptSelectMech, "[REDACTED]") {
		t.Errorf("choice prompt was not redacted: %+v", got)
	}
	if got.PromptMechChosen != "" {
		t.Errorf("empty mechanism field changed to %q", got.PromptMechChosen)
	}
}

func TestInteractiveLoginRedactsEarlierAnswerInLaterError(t *testing.T) {
	const firstAnswer = "654321MFA"
	start := `{"SessionId":"s1","TenantId":"t1","Challenges":[
		{"Mechanisms":[{"MechanismId":"m-first","Name":"OTP","AnswerType":"Text"}]}]}`
	srv := identityServer(t, start, func(t *testing.T, req advanceReq) string {
		switch req.MechanismID {
		case "m-first":
			return `{"success":true,"Result":{"Summary":"NewPackage","Challenges":[
				{"Mechanisms":[{"MechanismId":"m-second","Name":"OTP","AnswerType":"Text"}]}]}}`
		case "m-second":
			return `{"success":false,"Message":"Earlier answer was ` + firstAnswer + `"}`
		default:
			t.Fatalf("unexpected mechanism %q", req.MechanismID)
			return ""
		}
	})
	p := &scriptPrompter{answers: []string{firstAnswer, "second-answer"}}
	_, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), p)
	if err == nil || strings.Contains(err.Error(), firstAnswer) || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("earlier MFA answer reflection was not redacted: %v", err)
	}
}

// The password (UP) step passes the earlier answers too: an identity error on
// that step reflecting a prior MFA answer must be redacted like every other.
func TestInteractiveLoginRedactsEarlierAnswerInPasswordStepError(t *testing.T) {
	const firstAnswer = "654321MFA"
	start := `{"SessionId":"s1","TenantId":"t1","Challenges":[
		{"Mechanisms":[{"MechanismId":"m-first","Name":"OTP","AnswerType":"Text"}]}]}`
	srv := identityServer(t, start, func(t *testing.T, req advanceReq) string {
		switch req.MechanismID {
		case "m-first":
			return `{"success":true,"Result":{"Summary":"NewPackage","Challenges":[
				{"Mechanisms":[{"MechanismId":"m-up","Name":"UP","AnswerType":"Text"}]}]}}`
		case "m-up":
			return `{"success":false,"Message":"Earlier answer was ` + firstAnswer + `"}`
		default:
			t.Fatalf("unexpected mechanism %q", req.MechanismID)
			return ""
		}
	})
	p := &scriptPrompter{answers: []string{firstAnswer}}
	_, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), p)
	if err == nil || strings.Contains(err.Error(), firstAnswer) || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("earlier MFA answer reflected in the password step was not redacted: %v", err)
	}
}

// A long or multi-line challenge prompt reaches the Prompter intact: redaction
// replaces secrets but never truncates or reflows the question the user must
// answer.
func TestInteractiveLoginPromptReachesPrompterIntact(t *testing.T) {
	longPrompt := "line one of the security question\nline two: " + strings.Repeat("very long guidance ", 20) + "END"
	start := `{"SessionId":"s1","TenantId":"t1","Challenges":[
		{"Mechanisms":[{"MechanismId":"m-sq","Name":"SQ","AnswerType":"Text","PromptMechChosen":` + fmt.Sprintf("%q", longPrompt) + `}]}]}`
	srv := identityServer(t, start, func(t *testing.T, req advanceReq) string {
		return `{"success":true,"Result":{"Summary":"LoginSuccess","OAuthTokens":{"access_token":"tok-sq"}}}`
	})
	p := &scriptPrompter{answers: []string{"whatever"}}
	if _, err := loginClient(t, srv.URL).InteractiveLogin(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if len(p.prompts) != 1 || p.prompts[0] != longPrompt {
		t.Errorf("prompt was reshaped or truncated:\ngot  %q\nwant %q", p.prompts, longPrompt)
	}
}

// Mechanism identity fields (MechanismID, Name, AnswerType) reach the Prompter
// verbatim even when a credential happens to be a substring: a programmatic
// Prompter matches on them, and rewriting "EMAIL" to "E[REDACTED]" because the
// password is "MAIL" corrupts that match. Display prompt fields stay redacted.
func TestInteractiveLoginKeepsMechanismIdentityFieldsVerbatim(t *testing.T) {
	const password = "MAIL"
	start := `{"SessionId":"s1","TenantId":"t1","Challenges":[{"Mechanisms":[
		{"MechanismId":"m-email-MAIL","Name":"EMAIL","AnswerType":"Text","PromptSelectMech":"send MAIL code"},
		{"MechanismId":"m-otp","Name":"OTP","AnswerType":"Text"}]}]}`
	srv := identityServer(t, start, func(t *testing.T, req advanceReq) string {
		return `{"success":true,"Result":{"Summary":"LoginSuccess","OAuthTokens":{"access_token":"tok-mech"}}}`
	})
	c, err := New(Config{URL: srv.URL, Username: "cloudadmin@t", Password: password})
	if err != nil {
		t.Fatal(err)
	}
	c.oobPollInterval = 0
	p := &scriptPrompter{choices: []int{0}, answers: []string{"123456"}}
	if _, err := c.InteractiveLogin(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if len(p.mechanisms) != 1 {
		t.Fatalf("mechanism choices = %v", p.mechanisms)
	}
	got := p.mechanisms[0][0]
	if got.Name != "EMAIL" || got.MechanismID != "m-email-MAIL" || got.AnswerType != "Text" {
		t.Errorf("identity fields must be verbatim, got %+v", got)
	}
	if strings.Contains(got.PromptSelectMech, password) {
		t.Errorf("display prompt was not redacted: %q", got.PromptSelectMech)
	}
}

func TestPickMechanism(t *testing.T) {
	up := Mechanism{MechanismID: "m-up", Name: "UP"}
	email := Mechanism{MechanismID: "m-email", Name: "EMAIL"}
	otp := Mechanism{MechanismID: "m-otp", Name: "OTP"}
	cases := []struct {
		name         string
		mechs        []Mechanism
		passwordUsed bool
		choices      []int
		want         string
		wantErr      bool
	}{
		{"up preferred", []Mechanism{email, up}, false, nil, "m-up", false},
		{"up not repeated", []Mechanism{up, email}, true, []int{1}, "m-email", false},
		{"single auto", []Mechanism{email}, true, nil, "m-email", false},
		{"prompted choice", []Mechanism{email, otp}, true, []int{1}, "m-otp", false},
		{"empty", nil, false, nil, "", true},
	}
	for _, tc := range cases {
		got, err := pickMechanism(tc.mechs, tc.passwordUsed, &scriptPrompter{choices: tc.choices})
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: got err %v, wantErr %v", tc.name, err, tc.wantErr)
			continue
		}
		if err == nil && got.MechanismID != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got.MechanismID, tc.want)
		}
	}
}
