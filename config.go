package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/spf13/viper"
	"net/http"
	"os"
	"strings"
)

const Version = "1.0.3"

type CliOptions struct {
	ConfigFile    string
	Cookies       string
	Headers       string
	Proxy         string
	Debug         bool
	Concurrency   int
	DecodedParams bool
	SilentMode    bool
	Timeout       int
	ToSlack       bool
	Version       bool
	NoRedirects   bool
}

type Config struct {
	Rules          map[string]Rule   `mapstructure:"rules"`
	Slack          map[string]string `mapstructure:"slack"`
	Cookies        string
	Headers        map[string]string
	httpClient     *http.Client
	HasExtraParams bool
}

func verifyFlags(options *CliOptions) error {
	flag.StringVar(&options.ConfigFile, "c", "", "File path to config file, which contains fuzz rules")
	flag.StringVar(&options.ConfigFile, "config", "", "File path to config file, which contains fuzz rules")

	flag.StringVar(&options.Cookies, "cookies", "", "Cookies to add in all requests")
	flag.StringVar(&options.Headers, "H", "", "Headers to add in all requests. Multiple should be separated by semi-colon")
	flag.StringVar(&options.Headers, "headers", "", "Headers to add in all requests. Multiple should be separated by semi-colon")

	flag.StringVar(&options.Proxy, "proxy", "", "set proxy url example: http://127.0.0.1:8080")
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

	flag.BoolVar(&options.Version, "version", false, "Get the current version of qsfuzz")

	flag.BoolVar(&options.NoRedirects, "nr", false, "Do not follow redirects for HTTP requests (default is true, redirects are followed)")
	flag.BoolVar(&options.NoRedirects, "no-redirects", false, "Do not follow redirects for HTTP requests (default is true, redirects are followed)")

	flag.Parse()

	if options.Version {
		fmt.Println("qsfuzz version: " + Version)
		os.Exit(0)
	}

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
