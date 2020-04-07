package main

import (
	"flag"
	"fmt"
	"github.com/fatih/color"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

type Rule struct {
	Description string           `mapstructure:"description"`
	Injections  []string         `mapstructure:"injections"`
	ExtraParams []string         `mapstructure:"extraParams"`
	Expectation ExpectedResponse `mapstructure:"expectation"`
	Heuristics  HeuristicsRule   `mapstructure:"heuristics"`
}

type HeuristicsRule struct {
	Injection       string   `mapstructure:"injection"`
	BaselineMatches []string `mapstructure:"baselineMatches"`
}

type ExpectedResponse struct {
	Contents []string          `mapstructure:"responseContents"`
	Codes    []string          `mapstructure:"responseCodes"`
	Headers  map[string]string `mapstructure:"responseHeaders"`
	Lengths  []string          `mapstructure:"responseLength"`
}

type UrlInjection struct {
	BaselineUrl   string
	InjectedUrl   string
	HeuristicsUrl string
}

type Response struct {
	StatusCode    int
	Body          string
	Headers       http.Header
	ContentLength int
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

type Task struct {
	UrlInjection UrlInjection
	RuleData     Rule
	RuleName     string
}

var failedRequestsSent int
var successfulRequestsSent int
var config Config
var opts CliOptions
var evaluationResults []EvaluationResult
var responseCache map[string]Response

var printGreen = color.New(color.FgGreen).PrintfFunc()
var printRed = color.New(color.FgRed).FprintfFunc()
var printCyan = color.New(color.FgCyan).FprintfFunc()
var startTime = time.Now()

func main() {
	err := verifyFlags(&opts)
	if err != nil {
		fmt.Println(err)
		flag.Usage()
		os.Exit(1)
	}

	if err := loadConfig(opts.ConfigFile); err != nil {
		fmt.Println("Failed loading config:", err)
		os.Exit(1)
	}

	urls, err := getUrlsFromFile()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Create HTTP Transport and Client after parsing flags
	createClient()

	if !opts.SilentMode {
		printCyan(os.Stderr, "There are %v unique URL/Query String combinations. Time to inject each query string, 1 at a time!\n", len(urls))
	}

	tasks := make(chan Task)

	var wg sync.WaitGroup

	startTime := time.Now()

	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			for task := range tasks {
				task.execute()
			}
			wg.Done()
		}()
	}

	for _, u := range urls {
		for rule, ruleData := range config.Rules {
			fullUrl, err := url.Parse(u)
			// If URL can't be parsed, ignore and move on
			if err != nil {
				if opts.Debug {
					printRed(os.Stderr, "[%v] error parsing URL or query parameters for\n", rule)
				}
				continue
			}

			injectedUrls, err := getInjectedUrls(fullUrl, ruleData)
			if err != nil {
				if opts.Debug {
					printRed(os.Stderr, "[%v] error parsing URL or query parameters for\n", rule)
				}
				continue
			}
			if injectedUrls == nil {
				continue
			}

			for _, injectedUrl := range injectedUrls {
				tasks <- Task{RuleName: rule, RuleData: ruleData, UrlInjection: injectedUrl}
			}
		}
	}

	close(tasks)
	wg.Wait()

	secondsElapsed := time.Since(startTime).Seconds()
	printCyan(os.Stderr, "Evaluations complete! %v successful requests sent (%v failed): %v requests per second\n", successfulRequestsSent, failedRequestsSent, int(float64(successfulRequestsSent)/secondsElapsed))
}

func (t Task) execute() {
	resp, err := sendRequest(t.UrlInjection.InjectedUrl)
	if err != nil {
		failedRequestsSent += 1
		if opts.Debug {
			printRed(os.Stderr, "error sending HTTP request to %v: %v\n", t.UrlInjection.InjectedUrl, err)
		}
		return
	}
	successfulRequestsSent += 1

	heuristicsResponse := Response{}
	baselineResponse := Response{}
	if t.RuleData.Heuristics.Injection != "" {
		// Check if the baseline URL has already been requested to avoid duplicate requests
		if response, ok := responseCache[t.UrlInjection.BaselineUrl]; ok {
			baselineResponse = response
		} else {
			baselineResponse, err = sendRequest(t.UrlInjection.BaselineUrl)
			if err != nil {
				failedRequestsSent += 1
				if opts.Debug {
					printRed(os.Stderr, "error sending HTTP request to %v: %v\n", t.UrlInjection.BaselineUrl, err)
				}
			}
			successfulRequestsSent += 1
		}
		heuristicsResponse, err = sendRequest(t.UrlInjection.HeuristicsUrl)
		if err != nil {
			failedRequestsSent += 1
			if opts.Debug {
				printRed(os.Stderr, "error sending HTTP request to %v: %v\n", t.UrlInjection.HeuristicsUrl, err)
			}
		}
		successfulRequestsSent += 1
	}

	// Send an update every 1,000 requests
	if !opts.SilentMode {
		totalRequestsSent := successfulRequestsSent + failedRequestsSent
		if totalRequestsSent%1000 == 0 {
			secondsElapsed := time.Since(startTime).Seconds()
			fmt.Fprintf(os.Stderr, "%v requests sent (%v failed): %v requests per second\n", totalRequestsSent, failedRequestsSent, int(float64(successfulRequestsSent)/secondsElapsed))
		}
	}

	ruleEvaluation := t.RuleData.evaluate(resp, t.UrlInjection, t.RuleName, heuristicsResponse, baselineResponse)
	if ruleEvaluation.Successful {
		printGreen(ruleEvaluation.SuccessMessage)
		if opts.ToSlack {
			err = sendSlackMessage(ruleEvaluation.SuccessMessage)
			if err != nil && opts.Debug {
				printRed(os.Stderr, "error sending Slack message: %v\n", err)
			}
		}
	}
}
