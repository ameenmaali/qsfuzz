package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"github.com/spf13/viper"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

func VerifyFlags(options *CliOptions) error {
	flag.StringVar(&options.ConfigFile, "c", "", "File path to config file, which contains fuzz rules")
	flag.StringVar(&options.ConfigFile, "config", "", "File path to config file, which contains fuzz rules")

	flag.StringVar(&options.Cookies, "cookies", "", "Cookies to add in all requests")

	flag.StringVar(&options.Headers, "H", "", "Headers to add in all requests. Multiple should be separated by semi-colon")
	flag.StringVar(&options.Headers, "headers", "", "Headers to add in all requests. Multiple should be separated by semi-colon")

	flag.BoolVar(&options.Debug, "debug", false, "Debug/verbose mode to print more info for failed/malformed URLs or requests")

	flag.BoolVar(&options.SilentMode, "s", false, "Only print successful evaluations (i.e. mute status updates). Note these updates print to stderr, and won't be saved if saving stdout to files")
	flag.BoolVar(&options.SilentMode, "silent", false, "Only print successful evaluations (i.e. mute status updates). Note these updates print to stderr, and won't be saved if saving stdout to files")

	flag.BoolVar(&options.DecodedParams, "d", false, "Send requests with decoded query strings/parameters (this could cause many errors/bad requests)")
	flag.BoolVar(&options.DecodedParams, "decode", false, "Send requests with decoded query strings/parameters (this could cause many errors/bad requests)")

	flag.IntVar(&options.Concurrency, "w", 25, "Set the concurrency/worker count")
	flag.IntVar(&options.Concurrency, "workers", 25, "Set the concurrency/worker count")

	flag.Parse()

	if options.ConfigFile == "" {
		return errors.New("config file flag is required")
	}

	if options.Cookies != "" {
		config.Cookies = options.Cookies
	}

	if options.Headers != "" {
		headers := make(map[string]string)
		rawHeaders := strings.Split(options.Headers, ";")
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

func loadConfig(configFile string) error {
	// In order to ensure dots (.) are not considered as delimiters, set delimiter
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))

	v.SetConfigFile(configFile)
	if err := v.ReadInConfig(); err != nil {
		return err
	}

	if err := v.Unmarshal(&config); err != nil {
		return err
	}

	if err := v.UnmarshalKey("rules", &config); err != nil {
		return err
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

		// Use query string keys when sorting in order to get unique URL & Query String combinations
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
				// Check if templating is used in the injection, if so substitute it
				expandedInjection := expandTemplatedValues(injection, u)
				queryStrings[qs][index] = expandedInjection

				// TODO: Find a better solution to turn the qs map into a decoded string
				decodedQs, err := url.QueryUnescape(queryStrings.Encode())
				if err != nil {
					fmt.Println("Error decoding parameters: ", err)
					continue
				}

				if opts.DecodedParams {
					u.RawQuery = decodedQs
				} else {
					u.RawQuery = queryStrings.Encode()
				}

				replacedUrls = append(replacedUrls, u.String())

				// Set back to original qs val to ensure we only update one parameter at a time
				queryStrings[qs][index] = val
			}
		}
	}
	return replacedUrls, nil
}

// Makeshift templating check within the YAML files to allow for more dynamic config files
func expandTemplatedValues(ruleInjection string, u *url.URL) string {
	if !strings.Contains(ruleInjection, "[[") || !strings.Contains(ruleInjection, "]]") {
		return ruleInjection
	}

	re := regexp.MustCompile(`\[\[([^\[\]]*)\]\]`)

	templateMatches := re.FindAllString(ruleInjection, -1)
	for _, match := range templateMatches {
		if strings.ToLower(match) == "[[fullurl]]" {
			ruleInjection = strings.ReplaceAll(ruleInjection, match, url.QueryEscape(u.String()))
		}

		if strings.ToLower(match) == "[[domain]]" {
			ruleInjection = strings.ReplaceAll(ruleInjection, match, u.Host)
		}

		if strings.ToLower(match) == "[[path]]" {
			ruleInjection = strings.ReplaceAll(ruleInjection, match, u.Path)
		}

	}
	return ruleInjection
}
