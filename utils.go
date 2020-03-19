package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

func VerifyFlags(options *cliOptions) error {
	flag.StringVar(&options.configFilename, "c", "", "File path to config file, which contains fuzz rules")
	flag.StringVar(&options.configFilename, "config", "", "File path to config file, which contains fuzz rules")

	flag.StringVar(&options.cookies, "cookies", "", "Cookies to add in all requests")

	flag.StringVar(&options.headers, "H", "", "Headers to add in all requests. Multiple should be separated by semi-colon")
	flag.StringVar(&options.headers, "headers", "", "Headers to add in all requests. Multiple should be separated by semi-colon")

	flag.BoolVar(&options.verbose, "v", false, "Verbose mode to print more info for failed/malformed URLs or requests")
	flag.BoolVar(&options.verbose, "verbose", false, "Verbose mode to print more info for failed/malformed URLs or requests")

	flag.Parse()

	if options.configFilename == "" {
		return errors.New("config file flag is required")
	}

	if options.cookies != "" {
		config.Cookies = options.cookies
	}

	if options.headers != "" {
		headers := make(map[string]string)
		rawHeaders := strings.Split(options.headers, ";")
		for _, header := range rawHeaders {
			var parts []string
			if strings.Contains(header, ": ") {
				parts = strings.Split(header, ": ")
			} else {
				parts = strings.Split(header, ":")
			}
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
		config.Headers = headers
	}

	return nil
}

func GetUrlsFromFile() ([]string, error) {
	deduplicatedUrls := make(map[string]bool)
	var urls []string

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		providedUrl := scanner.Text()
		// Only include properly formatted URLs
		u, err := url.Parse(providedUrl)
		if err != nil {
			continue
		}

		// Go's maps aren't ordered, but we want to use all the param names
		// as part of the key to output only unique requests. To do that, put
		// them into a slice and then sort it.
		params := make([]string, 0)
		for param, _ := range u.Query() {
			params = append(params, param)
		}
		sort.Strings(params)

		key := fmt.Sprintf("%s%s?%s", u.Hostname(), u.EscapedPath(), strings.Join(params, "&"))

		// Only output each host + path + params combination once, regardless if different param values
		if _, exists := deduplicatedUrls[key]; exists {
			continue
		}
		deduplicatedUrls[key] = true

		urls = append(urls, u.String())
	}
	return urls, scanner.Err()
}

func getInjectedUrls(fullUrl string, ruleInjections []string) ([]string, error) {
	u, err := url.Parse(fullUrl)

	// If URL can't be parsed, ignore and move on
	if err != nil {
		return nil, err
	}

	// If query strings can't be parsed, set query strings as empty
	queryStrings, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, err
	}

	var replacedUrls []string
	for _, injection := range ruleInjections {
		for qs, values := range queryStrings {
			for index, val := range values {
				queryStrings[qs][index] = injection

				// TODO: Find a better solution to turn the qs map into a decoded string
				decodedQs, err := url.QueryUnescape(queryStrings.Encode())
				if err != nil {
					fmt.Println("Error decoding parameters: ", err)
					continue
				}

				u.RawQuery = decodedQs

				replacedUrls = append(replacedUrls, u.String())

				// Set back to original qs val to ensure we only update one parameter at a time
				queryStrings[qs][index] = val
			}
		}
	}
	return replacedUrls, nil
}
