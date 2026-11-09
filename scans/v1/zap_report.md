# ZAP Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Informational | 6 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| Info | Informational | http://127.0.0.1:5000 | Percentage of responses with status code 2xx | 60 % |
| Info | Informational | http://127.0.0.1:5000 | Percentage of responses with status code 3xx | 20 % |
| Info | Informational | http://127.0.0.1:5000 | Percentage of responses with status code 4xx | 20 % |
| Info | Informational | http://127.0.0.1:5000 | Percentage of endpoints with content type text/css | 12 % |
| Info | Informational | http://127.0.0.1:5000 | Percentage of endpoints with content type text/html | 87 % |
| Info | Informational | http://127.0.0.1:5000 | Percentage of endpoints with method GET | 75 % |
| Info | Informational | http://127.0.0.1:5000 | Percentage of endpoints with method POST | 25 % |
| Info | Informational | http://127.0.0.1:5000 | Count of total endpoints | 8    |







## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| Authentication Request Identified | Informational | 1 |
| Non-Storable Content | Informational | 2 |
| Session Management Response Identified | Informational | 6 |
| Storable and Cacheable Content | Informational | Systemic |
| Storable but Non-Cacheable Content | Informational | 1 |
| User Controllable HTML Element Attribute (Potential XSS) | Informational | 6 |




## Alert Detail



### [ Authentication Request Identified ](https://www.zaproxy.org/docs/alerts/10111/)



##### Informational (High)

### Description

The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to match the request identified.

* URL: http://127.0.0.1:5000/login
  * Node Name: `http://127.0.0.1:5000/login ()(csrf_token,password,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=ZAP
passwordParam=password
referer=http://127.0.0.1:5000/login
csrfToken=csrf_token`


Instances: 1

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/)



#### Source ID: 3

### [ Non-Storable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stored and cached, to improve performance.

* URL: http://127.0.0.1:5000
  * Node Name: `http://127.0.0.1:5000`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `302`
  * Other Info: ``
* URL: http://127.0.0.1:5000/
  * Node Name: `http://127.0.0.1:5000/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `302`
  * Other Info: ``


Instances: 2

### Solution

The content may be marked as storable by ensuring that the following conditions are satisfied:
The request method must be understood by the cache and defined as being cacheable ("GET", "HEAD", and "POST" are currently defined as cacheable)
The response status code must be understood by the cache (one of the 1XX, 2XX, 3XX, 4XX, or 5XX response classes are generally understood)
The "no-store" cache directive must not appear in the request or response header fields
For caching by "shared" caches such as "proxy" caches, the "private" response directive must not appear in the response
For caching by "shared" caches such as "proxy" caches, the "Authorization" header field must not appear in the request, unless the response explicitly allows it (using one of the "must-revalidate", "public", or "s-maxage" Cache-Control response directives)
In addition to the conditions above, at least one of the following conditions must also be satisfied by the response:
It must contain an "Expires" header field
It must contain a "max-age" response directive
For "shared" caches such as "proxy" caches, it must contain a "s-maxage" response directive
It must contain a "Cache Control Extension" that allows it to be cached
It must have a status code that is defined as cacheable by default (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501).

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ Session Management Response Identified ](https://www.zaproxy.org/docs/alerts/10112/)



##### Informational (Medium)

### Description

The given response has been identified as containing a session management token. The 'Other Info' field contains a set of header tokens that can be used in the Header Based Session Management Method. If the request is in a context which has a Session Management Method set to "Auto-Detect" then this rule will change the session management to use the tokens identified.

* URL: http://127.0.0.1:5000
  * Node Name: `http://127.0.0.1:5000`
  * Method: `GET`
  * Parameter: `session`
  * Attack: ``
  * Evidence: `session`
  * Other Info: `cookie:session`
* URL: http://127.0.0.1:5000/
  * Node Name: `http://127.0.0.1:5000/`
  * Method: `GET`
  * Parameter: `session`
  * Attack: ``
  * Evidence: `session`
  * Other Info: `cookie:session`
* URL: http://127.0.0.1:5000/login
  * Node Name: `http://127.0.0.1:5000/login`
  * Method: `GET`
  * Parameter: `session`
  * Attack: ``
  * Evidence: `session`
  * Other Info: `cookie:session`
* URL: http://127.0.0.1:5000/login
  * Node Name: `http://127.0.0.1:5000/login ()(csrf_token,password,username)`
  * Method: `POST`
  * Parameter: `session`
  * Attack: ``
  * Evidence: `session`
  * Other Info: `cookie:session`
* URL: http://127.0.0.1:5000/register
  * Node Name: `http://127.0.0.1:5000/register ()(confirm,csrf_token,email,password,username)`
  * Method: `POST`
  * Parameter: `session`
  * Attack: ``
  * Evidence: `session`
  * Other Info: `cookie:session`
* URL: http://127.0.0.1:5000/login
  * Node Name: `http://127.0.0.1:5000/login ()(csrf_token,password,username)`
  * Method: `POST`
  * Parameter: `session`
  * Attack: ``
  * Evidence: `session`
  * Other Info: `cookie:session`


Instances: 6

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/)



#### Source ID: 3

### [ Storable and Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, and may be retrieved directly from the cache, rather than from the origin server by the caching servers, in response to similar requests from other users. If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where "shared" caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.

* URL: http://127.0.0.1:5000
  * Node Name: `http://127.0.0.1:5000`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`
* URL: http://127.0.0.1:5000/login
  * Node Name: `http://127.0.0.1:5000/login`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`
* URL: http://127.0.0.1:5000/robots.txt
  * Node Name: `http://127.0.0.1:5000/robots.txt`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`
* URL: http://127.0.0.1:5000/sitemap.xml
  * Node Name: `http://127.0.0.1:5000/sitemap.xml`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`
* URL: http://127.0.0.1:5000/login
  * Node Name: `http://127.0.0.1:5000/login ()(csrf_token,password,username)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`

Instances: Systemic


### Solution

Validate that the response does not contain sensitive, personal or user-specific information. If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user:
Cache-Control: no-cache, no-store, must-revalidate, private
Pragma: no-cache
Expires: 0
This configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request.

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ Storable but Non-Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, but will not be retrieved directly from the cache, without validating the request upstream, in response to similar requests from other users.

* URL: http://127.0.0.1:5000/static/style.css
  * Node Name: `http://127.0.0.1:5000/static/style.css`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``


Instances: 1

### Solution



### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ User Controllable HTML Element Attribute (Potential XSS) ](https://www.zaproxy.org/docs/alerts/10031/)



##### Informational (Low)

### Description

This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability.

* URL: http://127.0.0.1:5000/login
  * Node Name: `http://127.0.0.1:5000/login ()(csrf_token,password,username)`
  * Method: `POST`
  * Parameter: `csrf_token`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://127.0.0.1:5000/login

appears to include user input in:
a(n) [input] tag [value] attribute

The user input found was:
csrf_token=8bce355fc6e80b0794153f92ecd3e04dcfc9c547b310b7b6bbc70a408a78f158

The user-controlled value was:
8bce355fc6e80b0794153f92ecd3e04dcfc9c547b310b7b6bbc70a408a78f158`
* URL: http://127.0.0.1:5000/register
  * Node Name: `http://127.0.0.1:5000/register ()(confirm,csrf_token,email,password,username)`
  * Method: `POST`
  * Parameter: `confirm`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://127.0.0.1:5000/register

appears to include user input in:
a(n) [input] tag [value] attribute

The user input found was:
confirm=ZAP

The user-controlled value was:
zap`
* URL: http://127.0.0.1:5000/register
  * Node Name: `http://127.0.0.1:5000/register ()(confirm,csrf_token,email,password,username)`
  * Method: `POST`
  * Parameter: `csrf_token`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://127.0.0.1:5000/register

appears to include user input in:
a(n) [input] tag [value] attribute

The user input found was:
csrf_token=8bce355fc6e80b0794153f92ecd3e04dcfc9c547b310b7b6bbc70a408a78f158

The user-controlled value was:
8bce355fc6e80b0794153f92ecd3e04dcfc9c547b310b7b6bbc70a408a78f158`
* URL: http://127.0.0.1:5000/register
  * Node Name: `http://127.0.0.1:5000/register ()(confirm,csrf_token,email,password,username)`
  * Method: `POST`
  * Parameter: `email`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://127.0.0.1:5000/register

appears to include user input in:
a(n) [input] tag [value] attribute

The user input found was:
email=zaproxy@example.com

The user-controlled value was:
zaproxy@example.com`
* URL: http://127.0.0.1:5000/register
  * Node Name: `http://127.0.0.1:5000/register ()(confirm,csrf_token,email,password,username)`
  * Method: `POST`
  * Parameter: `password`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://127.0.0.1:5000/register

appears to include user input in:
a(n) [input] tag [value] attribute

The user input found was:
password=ZAP

The user-controlled value was:
zap`
* URL: http://127.0.0.1:5000/register
  * Node Name: `http://127.0.0.1:5000/register ()(confirm,csrf_token,email,password,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://127.0.0.1:5000/register

appears to include user input in:
a(n) [input] tag [value] attribute

The user input found was:
username=ZAP

The user-controlled value was:
zap`


Instances: 6

### Solution

Validate all input and sanitize output it before writing to any HTML attributes.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)


#### CWE Id: [ 20 ](https://cwe.mitre.org/data/definitions/20.html)


#### WASC Id: 20

#### Source ID: 3


