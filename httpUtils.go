package main

import (
	"crypto/tls"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

var transport = &http.Transport{
	TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	DisableKeepAlives: true,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: time.Second,
	}).DialContext,
}

var httpClient = &http.Client{
	Transport: transport,
}

func sendRequest(u string) (Response, error) {
	response := Response{}

	request, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return response, err
	}

	request.Header.Add("User-Agent", "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

	// Add headers passed in as arguments
	for header, value := range config.Headers {
		request.Header.Add(header, value)
	}

	// Add cookies passed in as arguments
	request.Header.Add("Cookie", config.Cookies)

	resp, err := httpClient.Do(request)
	if err != nil {
		return response, err
	}

	if resp.Body == nil {
		return response, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return response, err
	}

	response.Body = string(body)
	response.Headers = resp.Header
	response.StatusCode = resp.StatusCode

	return response, err
}
