// Author : aine-rb from Sopra Steria (based on the script of thc202 from the OWASP ZAP development team)

// This script is heavily based on the "Simple Form-Based Authentication.js" template
// It can be used to authenticate in a webapplication via a form submission followed by a GET request
// The submit target for the form, the name of the username field, the name of the password field
// and the URL of the GET target need to be specified after loading the script.
// The username and the password need to be configured when creating any Users.

// The authenticate function is called whenever ZAP requires to authenticate, for a Context for which
// this script was selected as the Authentication Method. The function should send any messages that
// are required to do the authentication and should return a message with an authenticated response
// so the calling method.
//
// NOTE: Any message sent in the function should be obtained using the 'helper.prepareMessage()' method.


// Parameters:
//   helper - a helper class providing useful methods: prepareMessage(), sendAndReceive(msg)
//   paramsValues - the values of the parameters configured in the Session Properties - Authentication panel.
//                      The paramsValues is a map, having as keys the parameters names (as returned by the
//				    getRequiredParamsNames() and getOptionalParamsNames() functions below)
//   credentials - an object containing the credentials values, as configured in the Session Properties - Users panel.
//                      The credential values can be obtained via calls to the getParam(paramName) method. The param
//				    names are the ones returned by the getCredentialsParamsNames() below

// Script parameters:
const getLogin = "loginURL";
const userNameKey = "usernameKey";
const passwordKey =  "passwordKey"

// Request content types
const formEncoded = "application/x-www-form-urlencoded";
const appJson = "application/json";
const textHtml = "text/html; charset=utf-8";

// Detail the structure of authentication.users.credentials
const usernameParam = "username";
const passwordParam = "password";

// Make sure any Java classes used explicitly are imported
var HttpRequestHeader = Java.type('org.parosproxy.paros.network.HttpRequestHeader');
var HttpHeader = Java.type('org.parosproxy.paros.network.HttpHeader');
var URI = Java.type('org.apache.commons.httpclient.URI');
var AuthenticationHelper = Java.type('org.zaproxy.zap.authentication.AuthenticationHelper');
var HashMap = Java.type('java.util.HashMap');

/********* authenticate *************************************************************************************************************/

// The main function ofthis script fileCreatedDate
// paramsValues - the content of authentication.parameters
// credentials - the content of users.credentials
function authenticate(helper, paramsValues, credentials) {
    print("Authenticating TestFire via JavaScript script...");
    var url = paramsValues.get(getLogin);
    if (url.endsWith('/')) {
        url = url.slice(0, -1);
    }
	var username = credentials.getParam(usernameParam);
    var password = credentials.getParam(passwordParam);
	
	var requestBody = paramsValues.get(userNameKey).toLowerCase() + "=" + encodeURIComponent(username);
    requestBody += "&" + paramsValues.get(passwordKey).toLowerCase() + "=" + encodeURIComponent(password);
    
    var request = {
        method: HttpRequestHeader.POST,
        uri: new URI(url, false),
        body: requestBody,
        contentType: textHtml,
        cookies: null,
        authHeader: null,
        referer: null,
    };
    
    var loginResponse = authenticatePhase(helper, request, false);
    
    return loginResponse;
}

/********* Declaring script parameters **********************************************************************************************/

// This function is called during the script loading to obtain a list of the names of the required configuration parameters,
// that will be shown in the Session Properties -  Authentication panel for configuration. They can be used
// to input dynamic data into the script, from the user interface (e.g. a login URL, name of POST parameters etc.)
function getRequiredParamsNames(){
    return [getLogin, userNameKey, passwordKey];
}

// This function is called during the script loading to obtain a list of the names of the optional configuration parameters,
// that will be shown in the Session Properties -  Authentication panel for configuration. They can be used
// to input dynamic data into the script, from the user interface (e.g. a login URL, name of POST parameters etc.)
function getOptionalParamsNames(){
    return [];
}

// This function is called during the script loading to obtain a list of the names of the parameters that are required,
// as credentials, for each User configured corresponding to an Authentication using this script
function getCredentialsParamsNames(){
    return [usernameParam, passwordParam];
}

/********* Helper methods ***********************************************************************************************************/

// Receive a request and returns the response.
// If you wish to automatically follow redirects (3XX response setatus codes), set "follow" to true
function authenticatePhase(helper, request, follow) {
    if (!request || !request.uri || !request.method) {
        return null;
    }
    if ((request.method == HttpRequestHeader.POST || request.method == HttpRequestHeader.PUT) && !request.contentType) {
        request.contentType = formEncoded;
    }
    if (!follow) {
        follow = false;
    }

    var msg = helper.prepareMessage();
    var requestHeader = new HttpRequestHeader(request.method, request.uri, HttpHeader.HTTP11);

    setHeaders(requestHeader, request.cookies, request.authHeader, request.referer, request.contentType);

    var logMessage = ""
    if (request.body) {
        msg.setRequestBody(request.body);
        requestHeader.setContentLength(msg.getRequestBody().length());
        logMessage += " with body: " + request.body;
    }

    msg.setRequestHeader(requestHeader);

    // Send the submission request message
    print("Sending " + request.method + " request to " + request.uri + logMessage);
    helper.sendAndReceive(msg, follow); // don't follow redirects in order to set correctly the cookie
    var responseBody = msg.getResponseBody().toString();
    if (responseBody.length > 1000) {
        responseBody = "HTML";
    }

    print("Received response status code: " + msg.getResponseHeader().getStatusCode() + " body: " +responseBody );
    AuthenticationHelper.addAuthMessageToHistory(msg);

    return msg;
}

// Return a string that represents the cookies set by Set-Cookie response-headers
function getCookiesFromResponse(msg){
    var cookieCollection = new HashMap();
    var cookies = msg.getResponseHeader().getHttpCookies("");
    for (var iterator = cookies.iterator(); iterator.hasNext();) {
       var cookie = iterator.next();
       var cookieName = cookie.getName();
       var cookieValue = cookie.getValue();
        cookieCollection.put(cookieName, cookieValue);
    }

    return compileCookies(cookieCollection);
}

// Convert a HashMap to a string representing a cookie
function compileCookies(cookies) {
     var cookie = "";
     var first = true;
     var entries = cookies.entrySet().toArray();

     for (var index in entries){
        var current = entries[index];
        print("\ncurrent: " + current);

        if (!first) {
            cookie += "; ";
        }
        first = false;
        cookie += current;
     }
     print("\nCookie: " + cookie);
     return cookie;
}

function setHeaders(requestHeader, cookies, authHeader, referer, contentType) {

    if (contentType) {
        requestHeader.setHeader(HttpHeader.CONTENT_TYPE, contentType);
    }
    requestHeader.setHeader(HttpHeader.ACCEPT_ENCODING, "gzip, deflate, br");
    requestHeader.setHeader("Accept", "*/*");
    requestHeader.setHeader(HttpHeader.CONNECTION, HttpHeader._KEEP_ALIVE);

    if (cookies) {
        print("adding cookie: " + cookies);
        requestHeader.setHeader(HttpHeader.COOKIE, cookies);
    }
    if (authHeader) {
        requestHeader.setHeader(HttpHeader.AUTHORIZATION, authHeader);
    }
    if (referer) {
        requestHeader.setHeader(HttpHeader.REFERER, referer.toString());
    }
}

// Return the Location response-header as string
function getRedirect(msg) {

    print("Parsing an HTTP redirection resource...");

    var location = msg.getResponseHeader().getHeader(HttpHeader.LOCATION);
    if (location && location != "") {
        // Include the base url as well as some applications send relative URLs instead of absolute ones
        var baseURL = msg.getRequestHeader().getURI().toString();
        if (location.startsWith("/")) {
        location = baseURL + location;
        }
    }
    return location;
}

// Compare the two status codes, return the comparison and print an error if they do not match
function checkStatus(expected, actual) {
    print("response code is : " + actual);
    var result = expected == actual;
    if (!result) {
        print("Failed login; response status is : " + actual);
    }
    return result;
}

// encodeBase64 receive a string and return it as a Base64 encoded string
function encodeBase64(input) {
    if (typeof input != "sring" || input.length == 0 ){
        return "";
    }
    
    const keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    let output = "";
    let chr1, chr2, chr3, enc1, enc2, enc3, enc4;
    let i = 0;
    
    while (i < input.length) {
        chr1 = input.charCodeAt(i++);
        chr2 = input.charCodeAt(i++);
        chr3 = input.charCodeAt(i++);

        enc1 = chr1 >> 2;
        enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
        enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
        enc4 = chr3 & 63;

        if (isNaN(chr2)) {
            enc3 = enc4 = 64;
        } else if (isNaN(chr3)) {
            enc4 = 64;
        }
    
        output += keyStr.charAt(enc1) + keyStr.charAt(enc2) + keyStr.charAt(enc3) + keyStr.charAt(enc4);
    }
    
    return output;
}

//decodeBase64receive a  Base64 encoded string string and return the decoded string
function decodeBase64(input) {
    if (typeof input != "sring" || input.length == 0 ){
      return "";
    }
    const keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    let output = "";
    let chr1, chr2, chr3;
    let enc1, enc2, enc3, enc4;
    let i = 0;
  
    // Remove all characters that are not in the Base64 character set
    input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");
  
    while (i < input.length) {
        enc1 = keyStr.indexOf(input.charAt(i++));
        enc2 = keyStr.indexOf(input.charAt(i++));
        enc3 = keyStr.indexOf(input.charAt(i++));
        enc4 = keyStr.indexOf(input.charAt(i++));

        chr1 = (enc1 << 2) | (enc2 >> 4);
        chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
        chr3 = ((enc3 & 3) << 6) | enc4;

        output += String.fromCharCode(chr1);

        if (enc3 !== 64) {
           output += String.fromCharCode(chr2);
        }
        if (enc4 !== 64) {
           output += String.fromCharCode(chr3);
        }
    }
  
    return output;
}
