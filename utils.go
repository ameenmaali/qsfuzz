package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"github.com/spf13/viper"
	"math"
	"net/url"
	"os"
	"sort"
	"strings"
)

func verifyFlags(options *CliOptions) error {
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

	flag.IntVar(&options.Timeout, "t", 15, "Set the timeout length (in seconds) for each HTTP request")
	flag.IntVar(&options.Timeout, "timeout", 15, "Set the timeout length (in seconds) for each HTTP request")

	flag.BoolVar(&options.ToSlack, "ts", false, "Send positive matches to Slack (must have Slack key properly setup in config file)")
	flag.BoolVar(&options.ToSlack, "to-slack", false, "Send positive matches to Slack (must have Slack key properly setup in config file)")

	flag.Parse()

	if options.ConfigFile == "" {
		return errors.New("config file flag is required")
	}

	if options.Cookies != "" {
		config.Cookies = options.Cookies
	}

	if options.Headers != "" {
		if !strings.Contains(options.Headers, ":") {
			return errors.New("headers flag not formatted properly (no colon to separate header and value)")
		}
		headers := make(map[string]string)
		rawHeaders := strings.Split(options.Headers, ";")
		for _, header := range rawHeaders {
			var parts []string
			if strings.Contains(header, ": ") {
				parts = strings.Split(header, ": ")
			} else if strings.Contains(header, ":") {
				parts = strings.Split(header, ":")
			} else {
				continue
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

	if err := v.UnmarshalKey("slack", &config); err != nil {
		return err
	}

	// Ensure the Slack config in the config file has at least 2 keys (bot token and channel)
	if len(config.Slack) < 2 && opts.ToSlack {
		return errors.New(fmt.Sprintf("Slack flag enabled, but Slack config not adequately provided in %v\n", configFile))
	}

	// Add hashtag if the channel name is missing it
	if len(config.Slack) != 0 {
		if !strings.HasPrefix(config.Slack["channel"], "#") {
			config.Slack["channel"] = "#" + config.Slack["channel"]
		}
	}

	config.HasExtraParams = false
	// If any rules have extra params to be injected, set the config object to true to ensure URLs
	// with no query strings are also included
	for _, ruleValue := range config.Rules {
		if len(ruleValue.ExtraParams) != 0 {
			config.HasExtraParams = true
		}
	}

	return nil
}

func getUrlsFromFile() ([]string, error) {
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
		if len(queryStrings) == 0 && !config.HasExtraParams {
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

func getInjectedUrls(u *url.URL, rule Rule) ([]UrlInjection, error) {
	// If query strings can't be parsed, set query strings as empty
	queryStrings, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, err
	}

	var urlInjections []UrlInjection

	// Get extra rule injections if exists
	if len(rule.ExtraParams) != 0 && len(queryStrings) == 0 {
		for _, param := range rule.ExtraParams {
			if len(queryStrings[param]) != 0 {
				queryStrings.Add(param, "")
			}
		}
	}

	var expandedRuleInjections []string
	for _, ruleInjection := range rule.Injections {
		expandedRuleInjection, _ := expandTemplatedValues(ruleInjection, u, "", 0, nil)
		expandedRuleInjections = append(expandedRuleInjections, expandedRuleInjection)
	}

	for _, injection := range expandedRuleInjections {
		for qs, values := range queryStrings {
			for index, val := range values {
				_, expandedQs := expandTemplatedValues(injection, u, qs, index, queryStrings)
				urlInjection := UrlInjection{BaselineUrl: u.String()}

				queryStrings[qs][index] = expandedQs[qs][index]

				query, err := getInjectedQueryString(queryStrings)
				if err != nil {
					if opts.Debug {
						printRed(os.Stderr, "Error decoding parameters: ", err)
					}
				}

				u.RawQuery = query
				urlInjection.InjectedUrl = u.String()

				if rule.Heuristics.Injection != "" {
					queryStrings[qs][index] = val
					heuristicsInjection, _ := expandTemplatedValues(rule.Heuristics.Injection, u, "", 0, queryStrings)
					_, expandedQs := expandTemplatedValues(heuristicsInjection, u, qs, index, queryStrings)
					queryStrings[qs][index] = expandedQs[qs][index]
					query, err := getInjectedQueryString(queryStrings)
					if err != nil {
						if opts.Debug {
							printRed(os.Stderr, "Error decoding parameters: ", err)
						}
					}
					u.RawQuery = query
					urlInjection.HeuristicsUrl = u.String()
				}

				urlInjections = append(urlInjections, urlInjection)

				// Set back to original qs val to ensure we only update one parameter at a time
				queryStrings[qs][index] = val
			}
		}
	}
	return urlInjections, nil
}

// Makeshift templating check within the YAML files to allow for more dynamic config files
func expandTemplatedValues(ruleInjection string, u *url.URL, qs string, index int, queryStrings url.Values) (string, url.Values) {
	if !strings.Contains(ruleInjection, "[[") || !strings.Contains(ruleInjection, "]]") {
		return ruleInjection, queryStrings
	}

	replacer := strings.NewReplacer(
		"[[fullurl]]", url.QueryEscape(u.String()),
		"[[domain]]", u.Hostname(),
		"[[path]]", url.QueryEscape(u.Path),
	)

	if qs != "" {
		replacer = strings.NewReplacer(
			"[[fullurl]]", url.QueryEscape(u.String()),
			"[[domain]]", u.Hostname(),
			"[[path]]", url.QueryEscape(u.Path),
			"[[originalvalue]]", queryStrings.Get(qs),
		)
		queryStrings.Set(qs, replacer.Replace(ruleInjection))
	}

	return replacer.Replace(ruleInjection), queryStrings
}

func getInjectedQueryString(injectedQs url.Values) (string, error) {
	var qs string
	// TODO: Find a better solution to turn the qs map into a decoded string
	decodedQs, err := url.QueryUnescape(injectedQs.Encode())
	if err != nil {
		return "", err
	}

	if opts.DecodedParams {
		qs = decodedQs
	} else {
		qs = injectedQs.Encode()
	}

	return qs, nil
}

func isLengthWithinTenPercent(expectedLength int, responseLength int) bool {
	diff := int(math.Abs(float64(expectedLength) - float64(responseLength)))
	// Check if the diff is less than 10%, if so, consider a positive match
	if (diff/responseLength)*100 <= 10 {
		return true
	}
	return false
}
