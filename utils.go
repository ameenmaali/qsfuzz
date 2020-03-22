package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"github.com/spf13/viper"
	"net/url"
	"os"
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

		queryStrings := u.Query()

		// Only include URLs that have query strings
		if len(queryStrings) == 0 {
			continue
		}

		// Use query string keys when sorting in order to get unique URL & Query String combinations
		params := make([]string, 0)
		for param, _ := range queryStrings {
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

func getInjectedUrls(u *url.URL, ruleInjections []string) ([]string, error) {
	// If query strings can't be parsed, set query strings as empty
	queryStrings, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, err
	}

	var expandedRuleInjections []string
	for _, ruleInjection := range ruleInjections {
		expandedRuleInjection := expandTemplatedValues(ruleInjection, u)
		expandedRuleInjections = append(expandedRuleInjections, expandedRuleInjection)
	}

	var replacedUrls []string
	for _, injection := range expandedRuleInjections {
		for qs, values := range queryStrings {
			for index, val := range values {
				queryStrings[qs][index] = injection

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

	ruleInjection = strings.ReplaceAll(ruleInjection, "[[fullurl]]", url.QueryEscape(u.String()))
	ruleInjection = strings.ReplaceAll(ruleInjection, "[[domain]]", u.Host)
	ruleInjection = strings.ReplaceAll(ruleInjection, "[[path]]", url.QueryEscape(u.Path))
	return ruleInjection
}
