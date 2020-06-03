package tsiq

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type IQOSClient struct {
	URL          string
	AuthResponse *AuthResponse
	Quit         chan bool
}

type AuthResponse struct {
	TokenType   string        `json:"token_type"`
	ExpiresIn   time.Duration `json:"expires_in"`
	AccessToken string        `json:"access_token"`
	Scope       string        `json:"scope"`
}

type Submission struct {
	PolicyId      string `json:"policyId"`
	TransactionId string `json:"transactionId"`
}

type Submissions []Submission

func (c *IQOSClient) GetToken() error {
	url := "https://tsiq-auth.okta.com/oauth2/aus1h1wocz24PHuum2p7/v1/token"

	payload := strings.NewReader("grant_type=client_credentials&scope=default%20beta")
	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Basic MG9hMWR6dGp2dGlwMFloUzkycDc6THRMbDZCWFoyQW1DZi01c29Zcmx5d0phUVFzN0QydDJXS3dIVVBhZg==")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	res, _ := client.Do(req)
	body, _ := ioutil.ReadAll(res.Body)
	defer res.Body.Close()

	if err := json.Unmarshal(body, c.AuthResponse); err != nil {
		return err
	}
	return nil
}

func (c *IQOSClient) RefreshToken() {
	t := time.NewTicker(c.AuthResponse.ExpiresIn * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			fmt.Println("...Initiating token refresh!")
			c.GetToken()
		case <-c.Quit:
			fmt.Println("...Closing the channel and leaving!")
			return
		}
	}
}

func (c *IQOSClient) GetPolicyTransactions() ([]Submission, error) {
	url := "https://api-ea.twosigmaiq.com/policy-transactions?transactionState[0]=DRAFT&minEffectiveDate=2019-12-01&maxEffectiveDate=2020-07-31"
	req, _ := http.NewRequest("GET", url, bytes.NewReader([]byte("")))

	h := req.Header
	h.Add("Authorization", "Bearer "+c.AuthResponse.AccessToken)
	h.Add("Accept", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var subs []Submission
	if err := json.Unmarshal(body, &subs); err != nil {
		return nil, err
	}
	return subs, nil
}
