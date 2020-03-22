package main

import (
	"flag"
	"fmt"
	"github.com/fatih/color"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type CliOptions struct {
	ConfigFile    string
	Cookies       string
	Headers       string
	Debug         bool
	Concurrency   int
	DecodedParams bool
	SilentMode    bool
}

type Config struct {
	Rules   map[string]Rule `mapstructure:"rules"`
	Cookies string
	Headers map[string]string
}

type Rule struct {
	Description string           `mapstructure:"description"`
	Injections  []string         `mapstructure:"injections"`
	Expectation ExpectedResponse `mapstructure:"expectation"`
}

type ExpectedResponse struct {
	Contents []string          `mapstructure:"responseContents"`
	Codes    []int             `mapstructure:"responseCodes"`
	Headers  map[string]string `mapstructure:"responseHeaders"`
}

type Response struct {
	StatusCode int
	Body       string
	Headers    http.Header
}

type RuleEvaluation struct {
	ChecksMatched  int
	SuccessMessage string
	Successful     bool
}

type EvaluationResult struct {
	RuleName        string
	RuleDescription string
	InjectedUrl     string
}

type TaskData struct {
	InjectedUrl string
	RuleData    Rule
	RuleName    string
}

var failedRequestsSent int
var successfulRequestsSent int
var config Config
var opts CliOptions
var evaluationResults []EvaluationResult

func runEvaluation(resp Response, ruleData Rule, injectedUrl string, ruleName string) RuleEvaluation {
	headersExpected := false
	bodyExpected := false
	codeExpected := false

	numOfChecks := 0

	var ruleEvaluation RuleEvaluation

	if ruleData.Expectation.Headers != nil {
		headersExpected = true
		numOfChecks += 1
	}

	if ruleData.Expectation.Contents != nil {
		bodyExpected = true
		numOfChecks += 1
	}

	if ruleData.Expectation.Codes != nil {
		codeExpected = true
		numOfChecks += 1
	}

	if bodyExpected {
		for _, content := range ruleData.Expectation.Contents {
			if strings.Contains(strings.ToLower(resp.Body), strings.ToLower(content)) {
				ruleEvaluation.ChecksMatched += 1
			}
		}
	}

	if codeExpected {
		for _, code := range ruleData.Expectation.Codes {
			if code == resp.StatusCode {
				ruleEvaluation.ChecksMatched += 1
			}
		}
	}

	if headersExpected {
		for header, value := range ruleData.Expectation.Headers {
			if strings.Contains(strings.ToLower(resp.Headers.Get(header)), strings.ToLower(value)) {
				ruleEvaluation.ChecksMatched += 1
			}
		}
	}

	if ruleEvaluation.ChecksMatched > 0 && ruleEvaluation.ChecksMatched >= numOfChecks {
		ruleEvaluation.Successful = true
		u, err := url.QueryUnescape(injectedUrl)
		if err != nil {
			u = injectedUrl
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
		evaluationResults = append(evaluationResults, EvaluationResult{RuleName: ruleName, RuleDescription: ruleData.Description, InjectedUrl: injectedUrl})
	}

	return ruleEvaluation
}

func main() {
	printGreen := color.New(color.FgGreen).PrintfFunc()
	printRed := color.New(color.FgRed).PrintfFunc()
	printCyan := color.New(color.FgCyan).FprintfFunc()

	err := VerifyFlags(&opts)
	if err != nil {
		fmt.Println(err)
		flag.Usage()
		os.Exit(1)
	}

	if err := loadConfig(opts.ConfigFile); err != nil {
		fmt.Println("Failed loading config:", err)
		os.Exit(1)
	}

	urls, err := GetUrlsFromFile()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if !opts.SilentMode {
		printCyan(os.Stderr, "There are %v unique URL/Query String combinations. Time to inject each query string, 1 at a time!\n", len(urls))
	}

	tasks := make(chan TaskData)

	var wg sync.WaitGroup

	startTime := time.Now()

	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				task, ok := <-tasks
				// Return if tasks are complete
				if !ok {
					return
				}

				resp, err := sendRequest(task.InjectedUrl)
				if err != nil {
					failedRequestsSent += 1
					if opts.Debug {
						printRed("error sending HTTP request to %v: %v\n", task.InjectedUrl, err)
					}
					continue
				}

				successfulRequestsSent += 1

				// Send an update every 1,000 requests
				if !opts.SilentMode {
					totalRequestsSent := successfulRequestsSent + failedRequestsSent
					if totalRequestsSent%1000 == 0 {
						secondsElapsed := time.Since(startTime).Seconds()
						fmt.Fprintf(os.Stderr, "%v requests sent (%v failed): %v requests per second\n", totalRequestsSent, failedRequestsSent, int(float64(successfulRequestsSent)/secondsElapsed))
					}
				}

				ruleEvaluation := runEvaluation(resp, task.RuleData, task.InjectedUrl, task.RuleName)
				if ruleEvaluation.Successful {
					printGreen(ruleEvaluation.SuccessMessage)
				}
			}
		}()
	}

	for _, u := range urls {
		for rule, ruleData := range config.Rules {
			fullUrl, err := url.Parse(u)
			// If URL can't be parsed, ignore and move on
			if err != nil {
				if opts.Debug {
					printRed("[%v] error parsing URL or query parameters for\n", rule)
				}
				continue
			}

			injectedUrls, err := getInjectedUrls(fullUrl, ruleData.Injections)
			if err != nil {
				if opts.Debug {
					printRed("[%v] error parsing URL or query parameters for\n", rule)
				}
				continue
			}
			if injectedUrls == nil {
				continue
			}

			for _, injectedUrl := range injectedUrls {
				tasks <- TaskData{RuleName: rule, RuleData: ruleData, InjectedUrl: injectedUrl}
			}
		}
	}

	close(tasks)
	wg.Wait()

	secondsElapsed := time.Since(startTime).Seconds()
	printCyan(os.Stderr, "Evaluations complete! %v successful requests sent (%v failed): %v requests per second\n", successfulRequestsSent, failedRequestsSent, int(float64(successfulRequestsSent)/secondsElapsed))
}
