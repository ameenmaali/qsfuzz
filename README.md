# qsfuzz

qsfuzz (Query String Fuzz) is a tool that allows you to write simple rules in YAML that define what value you want to
inject, and what is the outcome you expect if that injection is successful. Pass in a list of URLs, with query strings,
and qsfuzz will replace the query string values with your injections to determine if it's vulnerable.

qsfuzz injections are done one-at-a-time for URLs with multiple query strings to ensure requests aren't broken if certain
parameters are relied on. URLs that don't have query strings will be ignored.

## Installation
```
go get github.com/ameenmaali/qsfuzz
```

## Usage
qsfuzz takes URLs (with query strings) from stdin, of which you will most likely want in a file such as:
```
$ cat file.txt
https://google.com/home/?q=2&d=asd
https://my.site/profile?param1=1&param2=2
https://my.site/profile?param3=3
```

qsfuzz also requires a config file (see `config-example.yaml` for an example) which contains the relevant rules to
evaluate against. This should be a YAML file and formatted such as:

```
$ cat config.yaml
rules:
  ruleName:
    description: This is my rule description
  injections:
    - injectionValue1
    - injectionValue2
  expectation:
    responseContents:
      - injectionValue1
    responseCodes:
      - 200
  rule2Name:
    description: This is my 2nd rule description
    injections:
      - '"><h2>asd</h2>'
    expectation:
      responseContents:
        - <h2>asd</h2>
      responseHeaders:
        Content-Type: html
slack:
  channel: "#channel-name"
  botToken: "MY-BOT-TOKEN"
```

#### Important Notes for Config files

You can have as many rules as you'd like (of course this will slow down evaluations). These are the currently supported fields,
annotated with comments above the field:

```yaml
# This should never change, and indicates the start of the rules list
rules:
  # This should be set to the rule's name you are defining
  ruleName:
    # This should be a short description of what the rule's purpose is
    description: 
    # This is a list (1 or more) of additional query strings to add to requests (that aren't already included in the URLs provided)
    # This will also keep all URLs that don't normally have query strings, and inject these params as the only ones.
    extraParams:
      - 
    # This is a list (1 or more) of injection values to inject within query strings
    injections:
      -
      -
    # There are several fields within expectation that will be defined below. At least 1 of the below categories must be present to be evaluated
    expectation:
      # This is a list (1 or more) of which include a value within a response body that should be present to indicate it is vulnerable.
      responseContents:
        -
      # This is a list (1 or more) of which include a response code that should be present to indicate it is vulnerable.
      responseCodes:
        -
      # This is a list (1 or more) of which include a response header that should be present to indicate it is vulnerable.
      responseHeaders:
        -
      # This is a list (1 or more) of which include a response length that should be within a 10% variance to indicate it is vulnerable.
      responseLengths:
        -
    # Including this heuristics key (optional) will do a couple things. It will send a request to a baseline URL with no parameter injections,
    # then match the baselineMatches expectations against the heuristic injection. 
    # (i.e. does injecting ' give a 500, but injecting '' in a query string match the baseline request with a 200 code)
    heuristics:
      # This is an injection that if successful matches the original baseline request baselineMatches
      injection: "''"
      # This is a list (1 or more) which check if the defined category matches the baseline request
      # (i.e. heuristic test match matches the baseline request)
      baselineMatches:
        - "responseCode"

# Optional key, to be used if -to-slack command line flag is enabled. Sends positive results to Slack
slack:
  # The Slack channel you wish to send results to
  channel: "#channel-name"
  # The bot token for your Slack app to use for authentication
  botToken: "MY-BOT-TOKEN"
```

For the `expectation` section, 3 types of matching are supported: `responseContents`, `responseCodes`, and `responseHeaders`
  - `responseContents` searches the response body for the contents within it
  - `responseCodes` matches against the response code of the request (redirects are followed automatically, however)
  - `responseHeaders` does a "contains" match against the response header. If `responseHeaders` is set to `html`, then a header value of `text/html` will successfully match
  - If you have more than 1 `expectation`, each of the evaluation categories must be matched for the evaluation to be successful, however only 1 of each category (i.e. `responseCodes`) needs to match

Take the following example:

```yaml
rules:
  XssDetection:
    description: This rule checks for reflected parameters
    injections:
      - '"><h2>asd</h2>'
      - <asd>test</asd>
    expectation:
      responseContents:
        - <h2>asd</h2>
        - <asd>test</asd>
      responseHeaders:
        Content-Type: html
```

The above rule will inject `"><h2>asd</h2>` and `<asd>test</asd>` in query string values, and check for `<h2>asd</h2>` OR `<asd>test</asd>` in the response contents.
In order to be successful, one of the 2 `responseContents` must be matched, as well as the `Content-Type` response header including `html` within it.

### Templating
There is rudimentary templating functionality within the rule's injection points, which can be done by inserting the supported variable in square brackets `[[var]]`. 
This is to allow for some dynamic payloads where you need them. Here are the following fields supported within the templating (these are all related to the URL that is 
being assessed at that point in time):
- `fullurl` (This is the full URL, including query strings, of the URL being targeted in a given request)
- `domain` (This is the domain of the URL being targeted in a given request)
- `path` (This is the path, not including query strings, of the URL being targeted in a given request)
- `originalvalue` (This is the query strings original value before being altered with the injection. i.e. `qs=asd` where `asd` is the original value)

An example on using these are:

```yaml
rules:
  CallbackFuzz:
    description: Test for open redirects and potential SSRFs by checking for certain responses or callbacks to your server
    extraParams:
      - url
      - redirect_url
    injections:
      - "http://[[domain]].example.net/"
      - "//example.net?targetUrl=[[fullurl]]"
      - "https://example.net?target=[[domain]][[path]]"
      - "@example.net"
    expectation:
      responseContents:
        - Example Domain
```

### Heuristics Based Testing
Including a `heuristics` key in your config file is optional. It will do a couple things:
1) It will send a request to a baseline URL with no parameter injections, and store that response
2) It will then match whatever categories are defined in the `baselineMatches` against the baseline request
3) Then, if both the rule injection are matched and the heuristics test, the rule will be a positive match.

Take the following example:

```yaml
SqlInjectionCheck:
  description: Test for potential SQL injections by injecting characters to break SQL statements
  injections:
    - "[[originalvalue]]'"
  expectation:
    responseCodes:
      - 500
  heuristics:
    injection: "[[originalvalue]]''"
    baselineMatches:
      - "responseCode"
```

This rule will first check for injecting `'` in query strings, appended to the query string's original value. If a response back is `500`, it will then do a heuristics based test.
A baseline request will be sent to understand what the endpoint normally returns without any injected query strings. Then, based
on the defined categories in `baselineMatches` (which in this case is `responseCode`), a check will be done to see if the response
code for the heuristic request matches the baseline request. So does `'` give a `500` response, but `''` gives a `200` response.

Including this key will result in more requests being sent, but there is some basic caching logic to ensure the same URLs aren't hit
more than necessary.

Currently, the supported `baselineMatches` are:
- `responseCode` (Matches the response code against the baseline request's response code)
- `responseLength` (Matches the response code against the baseline request's response length, within a 10% variance)
- `responseHeader` (Matches the response code against the baseline request's response headers. This is probably not very useful or worth using)
- `responseContent` (Matches the response code against the baseline request's response code. This is probably not very useful or worth using)

### Slack Integration
qsfuzz also supports sending positive matches to Slack. This can be done by adding in the following Slack Config in your config.yaml file.
This should be done as a separate key from `rules` (see above example), which is the `slack` key:

```yaml
slack:
  channel: "#channel-name"
  botToken: "MY-BOT-TOKEN"
```

This is particularly valuable in blind attacks, such as blind SSRF, where `qsfuzz` won't necessarily know whether it's successful, but your callback server receives a hit. 
You can add some data, such as the above supported parameters, within the injection to also send the vulnerable, injected URL within the request.

## Help
```
$ qsfuzz -h
Usage of qsfuzz:
  -H string
    	Headers to add in all requests. Multiple should be separated by semi-colon
  -c string
    	File path to config file, which contains fuzz rules
  -config string
    	File path to config file, which contains fuzz rules
  -cookies string
    	Cookies to add in all requests
  -d	
        Send requests with decoded query strings/parameters (this could cause many errors/bad requests)
  -debug
    	Debug/verbose mode to print more info for failed/malformed URLs or requests
  -decode
    	Send requests with decoded query strings/parameters (this could cause many errors/bad requests)
  -headers string
    	Headers to add in all requests. Multiple should be separated by semi-colon
  -no-redirects
    	Do not follow redirects for HTTP requests (default is true, redirects are followed)
  -nr
    	Do not follow redirects for HTTP requests (default is true, redirects are followed)
  -s	
        Only print successful evaluations (i.e. mute status updates). Note these updates print to stderr, and won't be saved if saving stdout to files
  -silent
    	Only print successful evaluations (i.e. mute status updates). Note these updates print to stderr, and won't be saved if saving stdout to files
  -t int
    	Set the timeout length (in seconds) for each HTTP request (default 15)
  -timeout int
    	Set the timeout length (in seconds) for each HTTP request (default 15)
  -to-slack
    	Send positive matches to Slack (must have Slack key properly setup in config file)
  -ts
    	Send positive matches to Slack (must have Slack key properly setup in config file)
  -version
    	Get the current version of qsfuzz
  -w int
    	Set the concurrency/worker count (default 25)
  -workers int
    	Set the concurrency/worker count (default 25)
```

## Examples

qsfuzz is best used when combining with other tools, such as hakcrawler or waybackurls

Get URLs from Wayback Machine with `waybackurls` and fuzz the parameters with `qsfuzz`

`cat hosts.txt | waybackurls | qsfuzz -c config.yaml`

Use cookies and headers for fuzzing:

`cat urls.txt | qsfuzz -c config.yaml -cookies "cookie1=value; cookie2=value2" -H "Authorization: Basic qosakdq==`

Crawl with hakrawler, assess with qsfuzz, and send results to Slack:

`cat hosts.txt | hakrawler | qsfuzz -c config.yaml -to-slack`
