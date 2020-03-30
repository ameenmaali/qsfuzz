package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

func sendSlackMessage(message string) error {
	slackUrl := "https://slack.com/api/chat.postMessage"
	content := map[string]interface{}{
		"channel": config.Slack["channel"],
		"text":    fmt.Sprintf("```%v```", message),
	}

	jsonContent, err := json.Marshal(content)
	if err != nil {
		return err
	}

	request, err := http.NewRequest("POST", slackUrl, bytes.NewReader(jsonContent))
	if err != nil {
		return err
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %v", config.Slack["bottoken"]))

	resp, err := config.httpClient.Do(request)
	if err != nil {
		return err
	}

	if resp.Body == nil {
		return err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	responseBody := make(map[string]interface{})
	err = json.Unmarshal(body, &responseBody)
	if err != nil {
		return err
	}

	if !responseBody["ok"].(bool) {
		return errors.New(responseBody["error"].(string))
	}

	return nil
}
