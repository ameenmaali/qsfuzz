package main

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
)

func (r *Rule) evaluate(resp Response, urlInjection UrlInjection, ruleName string, heuristicsResponse Response, baselineResponse Response) RuleEvaluation {
	headersExpected := false
	bodyExpected := false
	codeExpected := false
	lengthExpected := false
	heuristicsExpected := map[string]bool{"responsecode": false, "responselength": false, "responsecontent": false, "responseheader": false}

	numOfChecks := 0

	var ruleEvaluation RuleEvaluation

	if r.Expectation.Headers != nil {
		headersExpected = true
		numOfChecks += 1
	}

	if r.Expectation.Contents != nil {
		bodyExpected = true
		numOfChecks += 1
	}

	if r.Expectation.Codes != nil {
		codeExpected = true
		numOfChecks += 1
	}

	if r.Expectation.Lengths != nil {
		lengthExpected = true
		numOfChecks += 1
	}

	for _, match := range r.Heuristics.BaselineMatches {
		heuristicsExpected[strings.ToLower(match)] = true
	}

	if bodyExpected {
		if matched := r.evaluateContent(resp.Body, heuristicsResponse, baselineResponse, heuristicsExpected["responsecontent"]); matched {
			ruleEvaluation.ChecksMatched += 1
		}
	}

	if codeExpected {
		if matched := r.evaluateStatusCode(resp.StatusCode, heuristicsResponse, baselineResponse, heuristicsExpected["responsecode"]); matched {
			ruleEvaluation.ChecksMatched += 1
		}
	}

	if headersExpected {
		if matched := r.evaluateHeaders(resp.Headers, heuristicsResponse, baselineResponse, heuristicsExpected["responseheader"]); matched {
			ruleEvaluation.ChecksMatched += 1
		}
	}

	if lengthExpected {
		if matched := r.evaluateContentLength(resp.ContentLength, heuristicsResponse, baselineResponse, heuristicsExpected["responselength"]); matched {
			ruleEvaluation.ChecksMatched += 1
		}
	}

	if ruleEvaluation.ChecksMatched > 0 && ruleEvaluation.ChecksMatched >= numOfChecks {
		ruleEvaluation.Successful = true
		u, err := url.QueryUnescape(urlInjection.InjectedUrl)
		if err != nil {
			u = urlInjection.InjectedUrl
		}
		// Sprintf expects format string and arguments so URL encoded values will show up as (MISSING)
		// when printed. This will URL decode until fully decoded when printing for readability
		for strings.Contains(u, "%") {
			decodedUrl, err := url.QueryUnescape(u)
			if err != nil {
				break
			}
			u = decodedUrl
		}

		ruleEvaluation.SuccessMessage = fmt.Sprintf("[%s] successful match for %v\n", ruleName, u)
		evaluationResults = append(evaluationResults, EvaluationResult{RuleName: ruleName, RuleDescription: r.Description, InjectedUrl: urlInjection.InjectedUrl})
	}

	return ruleEvaluation
}

func (r *Rule) evaluateContent(responseContent string, heuristicsResponse Response, baselineResponse Response, heuristicExpected bool) bool {
	for _, content := range r.Expectation.Contents {
		if strings.Contains(strings.ToLower(responseContent), strings.ToLower(content)) {
			if !heuristicExpected {
				return true
			}

			if heuristicsResponse.Body == baselineResponse.Body {
				return true
			}
		}
	}
	return false
}

func (r *Rule) evaluateHeaders(responseHeaders http.Header, heuristicsResponse Response, baselineResponse Response, heuristicExpected bool) bool {
	for header, value := range r.Expectation.Headers {
		if strings.Contains(strings.ToLower(responseHeaders.Get(header)), strings.ToLower(value)) {
			if !heuristicExpected {
				return true
			}

			if reflect.DeepEqual(heuristicsResponse.Headers, baselineResponse.Headers) {
				return true
			}
		}
	}
	return false
}

func (r *Rule) evaluateStatusCode(responseCode int, heuristicsResponse Response, baselineResponse Response, heuristicExpected bool) bool {
	for _, code := range r.Expectation.Codes {
		statusCode, err := strconv.Atoi(code)
		if err != nil {
			continue
		}

		if statusCode == responseCode {
			if !heuristicExpected {
				return true
			}

			if heuristicsResponse.StatusCode == baselineResponse.StatusCode {
				// This is a false positive. If the heuristics response, baseline response, and injected response all have the same code
				// It is not an indication of vulnerable functionality
				if baselineResponse.StatusCode == responseCode {
					return false
				}
				return true
			}
		}
	}
	return false
}

func (r *Rule) evaluateContentLength(responseLength int, heuristicsResponse Response, baselineResponse Response, heuristicExpected bool) bool {
	for _, length := range r.Expectation.Lengths {
		expectedLength, err := strconv.Atoi(length)
		if err != nil {
			continue
		}

		if withinTenPercent := isLengthWithinTenPercent(expectedLength, responseLength); withinTenPercent {
			if !heuristicExpected {
				return true
			}

			if heuristicsMatch := isLengthWithinTenPercent(heuristicsResponse.ContentLength, baselineResponse.ContentLength); heuristicsMatch {
				return true
			}
		}
	}
	return false
}
