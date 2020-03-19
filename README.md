# qsfuzz

qsfuzz (Query String Fuzz) is a tool that allows you to write simple rules in YAML that define what value you want to
inject, and what is the outcome you expect if that injection is successful. Pass in a list of URLs, with query strings,
and qsfuzz will replace the query string values with your injections to determine if it's vulnerable.

qsfuzz injections are done one-at-a-time for URLs with multiple query strings to ensure requests aren't broken if certain
parameters are relied on.

## Installation
```
go get github.com/ameenmaali/qsfuzz
```

## Usage
qsfuzz takes URLs from stdin, of which you will most likely want in a file such as:
```
$ cat file.txt
https://google.com/home/?q=2&d=asd
https://my.site/profile?param1=1&param2=2
https://my.site/profile?param3=3
```

qsfuzz also requires a config file (see `config-example.yaml` for an example) which contains the relevant rules. This 
should be a YAML file and formatted such as:

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
```

*Important Notes for Config files*

You can have as many rules as you'd like (of course this will slow down evaluations)

For the `expectation` section, 3 types of matching are supported: `responseContents`, `responseCodes`, and `responseHeaders`
  - `responseContents` searches the response body for the contents within it
  - `responseCodes` matches against the response code of the request (redirects are followed automatically, however)
  - `responseHeaders` does a "contains" match against the response header. If `responseHeaders` is set to `html`, then a header value of `text/html` will successfully match
  - If you have more than 1 `expectation`, each of the evaluation categories must be matched for the evaluation to be successful, however only 1 of each category (i.e. `responseCodes`) needs to match

Take the following example:

```
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

## Help
```
$ qsfuzz -h
Usage of qsfuzz:
  -c string
    	File path to config file, which contains fuzz rules
  -config string
    	File path to config file, which contains fuzz rules
  -cookies string
    	Cookies to add in all requests
  -H string
    	Headers to add in all requests. Multiple should be separated by semi-colon
  -headers string
    	Headers to add in all requests. Multiple should be separated by semi-colon
  -v	
        Verbose mode to print more info for failed/malformed URLs or requests
  -verbose
    	Verbose mode to print more info for failed/malformed URLs or requests
```

## Examples

qsfuzz is best used when combining with other tools, such as hakcrawler or waybackurls

Get URLs from Wayback Machine with `waybackurls` and fuzz the parameters with `qsfuzz`

`cat hosts.txt | waybackurls | qsfuzz -c config.yaml`

Use cookies and headers for fuzzing:

`cat urls.txt | qsfuzz -c config.yaml -cookies "cookie1=value; cookie2=value2" -H "Authorization: Basic qosakdq==`
