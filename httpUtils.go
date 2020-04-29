package main

import (
	"crypto/tls"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/EDDYCJY/fake-useragent"
)

func createClient() {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(opts.Timeout) * time.Second,
			KeepAlive: time.Second,
		}).DialContext,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(opts.Timeout+3) * time.Second,
	}
	config.httpClient = httpClient
}

func sendRequest(u string) (Response, error) {
	response := Response{}

	request, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return response, err
	}

	request.Header.Add("User-Agent", browser.Random())

	// Add headers passed in as arguments
	for header, value := range config.Headers {
		request.Header.Add(header, value)
	}

	// Add cookies passed in as arguments
	request.Header.Add("Cookie", config.Cookies)

	resp, err := config.httpClient.Do(request)

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
	response.ContentLength = int(resp.ContentLength)

	return response, err
}
