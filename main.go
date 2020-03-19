package main

import (
	"flag"
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/viper"
	"net/http"
	"os"
	"strings"
	"sync"
)

type cliOptions struct {
	configFilename string
	cookies        string
	headers        string
	verbose        bool
}

type Config struct {
	Rules map[string]Rule `mapstructure:"rules"`
	Cookies string
	Headers map[string]string
}

type Rule struct {
	Description string           `mapstructure:"description"`
	Injections  []string         `mapstructure:"injections"`
	Expectation ExpectedResponse `mapstructure:"expectation"`
}

type ExpectedResponse struct {
	Contents []string                 `mapstructure:"responseContents"`
	Codes    []int                    `mapstructure:"responseCodes"`
	Headers  map[string]string `mapstructure:"responseHeaders"`
}

type Response struct {
	StatusCode int
	Body   string
	Headers    http.Header
}

type settings struct {
	SupportEnabled         bool
	ThirdPartyCrawlEnabled bool
	CrawlTimeThreshold     int
}

type RuleEvaluation struct {
	ChecksMatched int
	SuccessMessage string
	Successful bool
}

var config Config
var Settings settings

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

func runEvaluations(resp Response, ruleData Rule, injectedUrl string, ruleName string) RuleEvaluation {
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
			if strings.Contains(resp.Body, content) {
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
			if strings.Contains(resp.Headers.Get(header), value) {
				ruleEvaluation.ChecksMatched += 1
			}
		}
	}

	if ruleEvaluation.ChecksMatched >= numOfChecks {
		ruleEvaluation.Successful = true
		ruleEvaluation.SuccessMessage = fmt.Sprintf("[%v] successful match for %v\n", ruleName, injectedUrl)
	}

	return ruleEvaluation
}


func main() {
	printGreen := color.New(color.FgGreen).PrintfFunc()
	printRed := color.New(color.FgRed).PrintfFunc()

	opts := cliOptions{}

	err := VerifyFlags(&opts)
	if err != nil {
		fmt.Println(err)
		flag.Usage()
		os.Exit(1)
	}

	if err := loadConfig(opts.configFilename); err != nil {
		fmt.Println("Failed loading settings:", err)
		os.Exit(1)
	}

	urls, err := GetUrlsFromFile()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var wg sync.WaitGroup
	for _, u := range urls {
		wg.Add(1)
		go func(site string) {
			defer wg.Done()
			for rule, ruleData := range config.Rules {
				injectedUrls, err := getInjectedUrls(site, ruleData.Injections)
				if err != nil {
					if opts.verbose {
						printRed("[%v] error parsing URL or query parameters for\n", rule)
					}
					continue
				}
				if injectedUrls == nil {
					continue
				}

				for _, injectedUrl := range injectedUrls {
					resp, err := sendRequest(injectedUrl)
					if err != nil {
						if opts.verbose {
							printRed("error sending HTTP request (%v)\n", injectedUrl)
						}
						continue
					}

					ruleEvaluation := runEvaluations(resp, ruleData, injectedUrl, rule)
					if ruleEvaluation.Successful {
						printGreen(ruleEvaluation.SuccessMessage)
					}

				}
			}
		}(u)
	}
	wg.Wait()
}
