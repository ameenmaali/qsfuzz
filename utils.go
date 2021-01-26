package main

import (
	"bufio"
	"fmt"
	"math"
	"net/url"
	"os"
	"sort"
	"strings"
)

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

		// Only include URLs that have query strings unless extra params are provided
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
	if len(rule.ExtraParams) != 0 {
		for _, param := range rule.ExtraParams {
			if len(queryStrings[param]) == 0 {
				queryStrings.Add(param, "")
			}
		}
	}

	var expandedRuleInjections []string
	for _, ruleInjection := range rule.Injections {
		expandedRuleInjection := expandInjectionTemplates(ruleInjection, u)
		expandedRuleInjections = append(expandedRuleInjections, expandedRuleInjection)
	}

	for _, injection := range expandedRuleInjections {
		for qs, values := range queryStrings {
			for index, val := range values {
				// Only care about the first qs value if there's more than one of the same qs
				if index > 0 {
					continue
				}
				expandedQs := expandQsValueTemplates(injection, qs, queryStrings)
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
					heuristicsInjection := expandInjectionTemplates(rule.Heuristics.Injection, u)
					expandedQs := expandQsValueTemplates(heuristicsInjection, qs, queryStrings)
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
func expandInjectionTemplates(ruleInjection string, u *url.URL) string {
	if !strings.Contains(ruleInjection, "[[") || !strings.Contains(ruleInjection, "]]") {
		return ruleInjection
	}

	replacer := strings.NewReplacer(
		"[[fullurl]]", url.QueryEscape(u.String()),
		"[[domain]]", u.Hostname(),
		"[[path]]", url.QueryEscape(u.Path),
	)

	return replacer.Replace(ruleInjection)
}

func expandQsValueTemplates(ruleInjection string, qs string, queryStrings url.Values) url.Values {
	replacer := strings.NewReplacer(
		"[[originalvalue]]", queryStrings.Get(qs),
	)
	queryStrings.Set(qs, replacer.Replace(ruleInjection))
	return queryStrings

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
	// Cannot divide by 0 if empty response
	if responseLength == 0 {
		return false
	}

	diff := int(math.Abs(float64(expectedLength) - float64(responseLength)))

	// Check if the diff is less than 10%, if so, consider a positive match
	if (diff/responseLength)*100 <= 10 {
		return true
	}
	return false
}
