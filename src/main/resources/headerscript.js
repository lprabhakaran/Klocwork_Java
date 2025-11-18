/*
* This script is intended to be used along with authentication/OfflineTokenRefresher.js to
* handle an OAUTH2 offline token refresh workflow.
*
* authentication/OfflineTokenRefresher.js will automatically fetch the new access token for every unauthorized
* request determined by the "Logged Out" or "Logged In" indicator previously set in Context -> Authentication.
*
*  httpsender/AddBearerTokenHeader.js will add the new access token to all requests in scope
* made by ZAP (except the authentication ones) as an "Authorization: Bearer [access_token]" HTTP Header.
*
* @author Laura Pardo <lpardo at redhat.com>
*/

var HttpSender = Java.type('org.parosproxy.paros.network.HttpSender');
var ScriptVars = Java.type('org.zaproxy.zap.extension.script.ScriptVars');



/*
 * Processes messages by adding user-specified headers (overwriting original
 * values if header already exists). This may be pointless for some initiators
 * (CHECK_FOR_UPDATES) and redundant for others (FUZZER).
 *
 * Called before forwarding the message to the server.
 *
 * @param {HttpMessage} msg - The message that will be forwarded to the server.
 * @param {int} initiator - The initiator that generated the message.
 * @param {HttpSenderScriptHelper} helper - A utility object with helper functions.
 */


function sendingRequest(msg, initiator, helper) {

  // add Authorization header to all request in scope except the authorization request itself
var typeOfAuth = ScriptVars.getGlobalVar("authenticationType")
var authenticationKey = ScriptVars.getGlobalVar("authenticationKey")
var authorizationToken = ScriptVars.getGlobalVar("authorizationToken")
if(authorizationToken != null){
	msg.getRequestHeader().setHeader('Authorization', authenticationKey + ' ' + authorizationToken);
}

// Get user-supplied headers if we didn't already do it
var requestHeaders = ScriptVars.getGlobalVar("requestHeaders");
if(requestHeaders  != null){
user_headers = JSON.parse(ScriptVars.getGlobalVar("requestHeaders"));
	

// Ensure each header is present with the required value
    for (var key in user_headers) {
        var value = user_headers[key];
        // logger("Setting " + key + " to " + value);
        msg.getRequestHeader().setHeader(key, value);
    }

}

}

/* Called after receiving the response from the server.
 *
 * @param {HttpMessage} msg - The message that was forwarded to the server.
 * @param {int} initiator - The initiator that generated the message.
 * @param {HttpSenderScriptHelper} helper - A utility object with helper functions.
 */
function responseReceived(msg, initiator, helper) {
	// Nothing to do here
}