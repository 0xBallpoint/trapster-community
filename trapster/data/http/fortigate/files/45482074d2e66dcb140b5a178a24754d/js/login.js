/* SPDX-License-Identifier: LicenseRef-Fortinet */
/* eslint-disable */
var my_xmlhttp = null;
var buf_request_in_progress = false;
var token_push_request_in_progress = false;
var ftm_push_status_timeout = null;

var elm_username = document.getElementById("username");
var elm_secretkey = document.getElementById("secretkey");
var elm_loginButtonContainer = document.getElementById("login-button-container");
var elm_credentialContainer = document.getElementById("credential-fields");
var elm_contentContainer = document.getElementsByClassName("content");

var elm_twofactor = document.getElementById("auth_two_factor");
var elm_authtoken = document.getElementById("auth_token");

var elm_tokenmsg = document.getElementById("token_msg");
var elm_tokencode = document.getElementById("token_code");
var elm_ftm_push_enabled = document.getElementById("ftm_push_enabled");
var ftm_fgt_pushed_enabled  = Number(elm_ftm_push_enabled && elm_ftm_push_enabled.value);

var elm_button = document.getElementById("login_button");

// provide lang translation
var str_table = fgt_lang;

// Defined in /migbase/include/login.h
var GUI_LOGIN_STATUS_OK                 = '1',
    GUI_LOGIN_STATUS_LOCKOUT            = '2',
    GUI_LOGIN_STATUS_NEED_TFA           = '3',
    GUI_LOGIN_STATUS_CHANGE_PWD         = '4',
    GUI_LOGIN_STATUS_FTM_PUSH_PARAMS    = "5",
    GUI_LOGIN_STATUS_FTM_PUSH_STATUS    = "6",
    GUI_LOGIN_STATUS_FTM_PUSH_FAILURE   = "7";

// Defined in migbase/include/parser.h
const APS_TFA_DISABLE = 0;
const APS_TFA_FORTITOKEN = 1;
const APS_TFA_EMAIL = 2;
const APS_TFA_SMS = 3;
const APS_TFA_FORTITOKEN_FAC = 6;
const APS_TFA_FORTITOKEN_FAC_PUSH = 7;

// Defined in /migbase/include/fnbam.h
var FNBAM_SUCCESS   = '0',
    FNBAM_DENIED    = '1',
    FNBAM_PENDING   = '4',
    FNBAM_ERROR     = '5';
    FNBAM_NEED_TOKEN = '7';

function getQueryValue(url, name) {
    name = name.replace(/[\[]/, '\\[').replace(/[\]]/, '\\]');
    var regexS = '[\\?&]' + name + '=([^&#]*)';
    var regex = new RegExp(regexS);
    var results = regex.exec(url);
    if (!results) { return; }
    return decodeURIComponent(results[1].replace(/\+/g, " "));
}

function login_sso(url) {
	url += '?fallback=' + encodeURIComponent(location.origin + '/login');
	var redir = getQueryValue(location.href, 'redir');
	if (redir) {
		url += '&redir=' + encodeURIComponent(redir);
	}
	location.href = url;
}
function login_forticloud(url) {
	url += '?fallback=' + encodeURIComponent(location.origin + '/login');
	url += '&host=' + encodeURIComponent(location.host);
	var redir = getQueryValue(location.href, 'redir');
	if (redir) {
		url += '&redir=' + encodeURIComponent(redir);
	}
	location.href = url;
}

// login_send_request - send the login request as an Ajax message.
function login_send_request(str_url, str_body)
{
	my_xmlhttp = new XMLHttpRequest();
	my_xmlhttp.onreadystatechange = handle_buffer_statechange;

	my_xmlhttp.open("POST", str_url, true);
	my_xmlhttp.setRequestHeader("Pragma", "no-cache");
	my_xmlhttp.setRequestHeader("Cache-Control", "no-store, no-cache, must-revalidate");
	my_xmlhttp.setRequestHeader("If-Modified-Since", "Sat, 1 Jan 2000 00:00:00 GMT");
	my_xmlhttp.send(str_body);
}

// handle_buffer_statechange - onreadystatechange callback for the Ajax request.
function handle_buffer_statechange(ev)
{
	if (my_xmlhttp.readyState == 4) // 4 == complete
	{
		handle_buffer_ready();
	}
}
function addQuery(key)
{
	var xstr = '';
	var value = getQueryValue(location.href, key);
	if (value) {
		xstr += "&" + key + "=" + encodeURIComponent(value);
	}
	return xstr;
}

// try_login - begin the login process.
function try_login()
{
	if (buf_request_in_progress && !token_push_request_in_progress)
	{
		throw("Avoid sending conflicting request\n");
		return;
	}

	if (token_push_request_in_progress) {
		abort_current_request();
	}

	buf_request_in_progress = true;

	var xstr = "ajax=1&username=" + encodeURIComponent(elm_username.value) +
			   "&secretkey=" + encodeURIComponent(elm_secretkey.value);

	if (elm_twofactor && elm_authtoken)
	{
		xstr += "&auth_two_factor=1&auth_token=" + encodeURIComponent(elm_authtoken.value);
	}

	if (elm_tokencode && (elm_tokencode.disabled == false))
	{
		xstr += "&token_code=" + encodeURIComponent(elm_tokencode.value);
	}

	xstr += addQuery('redir');
	xstr += addQuery('saml_idp');

	clear_error_status_line();
	disable_input();

	try
	{
		const uri = window.location.pathname === '/fabric-authorization' ?
			'/fabric-logincheck' : '/logincheck';
		login_send_request(uri, xstr);
	}
	catch (e)
	{
		buf_request_in_progress = false;
		token_push_request_in_progress = false;
		update_error_status_line(str_table.server_unreachable);
		reenable_input();
		abort_current_request();
	}
}

function trigger_ftm_push(isFacAuth) {
	if (buf_request_in_progress) {
		return;
	}

	buf_request_in_progress = true;
    token_push_request_in_progress = true;

	const param = isFacAuth ? 'ftm_fac_push_trigger' : 'ftm_push_trigger';
	var xstr = `ajax=1&username=${encodeURIComponent(elm_username.value)}` +
			`&${param}=1${addQuery('redir')}${addQuery('saml_idp')}`;

	try {
		const uri = window.location.pathname === '/fabric-authorization' ?
			'/fabric-logincheck' : '/logincheck';
		login_send_request(uri, xstr);
	} catch (e) {
		buf_request_in_progress = false;
		token_push_request_in_progress = false;
		abort_current_request();
	}
}

function get_ftm_push_status(query_params) {
	if (buf_request_in_progress) {
		return;
	}

	buf_request_in_progress = true;

	var xstr = "ajax=1&username=" + encodeURIComponent(elm_username.value) +
			   "&secretkey=" + encodeURIComponent(elm_secretkey.value) +
			   "&ftm_push_status=1" + '&' + query_params +
			   addQuery('redir') + addQuery('saml_idp');

	try {
		const uri = window.location.pathname === '/fabric-authorization' ?
			'/fabric-logincheck' : '/logincheck';
		login_send_request(uri, xstr);
	} catch (e) {
		buf_request_in_progress = false;
		abort_current_request();
	}
}

function start_ftm_push_poll(query_params) {
	cancel_ftm_push_poll();
	get_ftm_push_status(query_params);
	ftm_push_status_timeout = setTimeout(function() {
		start_ftm_push_poll(query_params);
	}, 2000);
}

function cancel_ftm_push_poll() {
	clearTimeout(ftm_push_status_timeout);
}

// Display a message in red above the username.
// Flash the colour between black and red to draw the user's attention (in particular when
// the error message is the same as the one from the previous request).
function update_error_status_line(msg)
{
    document.getElementById("err_msg_content").textContent = msg;
    document.getElementById("err_msg").style.display = null;
}

function clear_error_status_line()
{
    document.getElementById("warn_msg").style.display = 'none';
    document.getElementById("err_msg").style.display = 'none';
}

function update_warning_status_line(msg)
{
    document.getElementById("warn_msg_content").textContent = msg;
    document.getElementById("warn_msg").style.display = null;
}


// handle_buffer_ready - function to handle the Ajax response. The first
// character of the response is the status code (0 is failure, 1 is success,
// and 2 is a special case for the 1 minute lockout). If success, the
// remainder of the string contains a JS function to redirect to the main page.
function handle_buffer_ready()
{
	// Check & reset semaphore.
	if (!buf_request_in_progress) {
		return;
	}

	buf_request_in_progress = false;
    token_push_request_in_progress = false;

	var retval = my_xmlhttp.responseText;

	my_xmlhttp = null;

	if (retval.length == 0)
	{
		update_error_status_line(str_table.server_unreachable);
		reenable_input();
		return;
	}

	var rv = retval.charAt(0);
	var rv2 = retval.substring(1);

	if (rv == GUI_LOGIN_STATUS_OK)
	{
		// Originally the rv was a document containing JS.
		// Now it's just JS.
		eval(rv2);
	}
	else if (rv == GUI_LOGIN_STATUS_LOCKOUT)
	{
		// rv = 2 is for 1 minute lockout
		update_error_status_line(str_table.lockout_msg);

		// Leave form fields during lockout period.
		setTimeout("reenable_input();", 60 * 1000);
	}
	else if (rv == GUI_LOGIN_STATUS_NEED_TFA)
	{
		//2-factor auth needed: tokencode
		update_error_status_line(str_table.token_needed);

		showToken(true, parseInt(rv2[0]), retval.substring(2));
		elm_button.disabled = false;
		elm_tokencode.focus();

	}
	else if (rv === GUI_LOGIN_STATUS_CHANGE_PWD)
	{
		// Admin must change their password because
		// a password policy requires the change
		eval(rv2);
	}
	else if (rv === GUI_LOGIN_STATUS_FTM_PUSH_PARAMS)
	{
		start_ftm_push_poll(rv2);
	}
	else if (rv === GUI_LOGIN_STATUS_FTM_PUSH_STATUS)
	{
		if (rv2 !== FNBAM_NEED_TOKEN) {
			// Kill poll
			cancel_ftm_push_poll();
		}
	}
	else if (rv === GUI_LOGIN_STATUS_FTM_PUSH_FAILURE) {
		// Kill poll
		cancel_ftm_push_poll();
	}
	else
	{
		update_error_status_line(str_table.login_failed);
		clear_input();
		cancel_ftm_push_poll();
		reenable_input();
		showToken(false);
	}
}

function disable_input()
{
	elm_username.disabled = true;
	elm_secretkey.disabled = true;
}

function reenable_input()
{
	var two_factor_auth = (!!document.getElementById("auth_two_factor"));

	elm_username.disabled = false;
	elm_secretkey.disabled = false;
	elm_button.disabled = false;
	elm_tokencode.disabled = false;

	// Blur and set the focus on username
	elm_username.blur();

	if (two_factor_auth)
		elm_secretkey.focus();
	else
		elm_username.focus();
}

// login_get_cmd_kbd_event and login_crack_kbd_event are the copies of
// get_cmd_kbd_event and crack_kbd_event from jsconsole.js
// login_get_cmd_kbd_event - same as get_cons_kbd_event, but uses different document object
function login_get_cmd_kbd_event(evt_p)
{
	if (evt_p)
		return evt_p;
	evt = window.event;
	if (evt)
		return evt;
	return null;
}

// login_crack_kbd_event - Returns the keypress code associated with the event.
function login_crack_kbd_event(evt)
{
	if (evt.which)
		return evt.which;
	else if (evt.keyCode)
		return evt.keyCode;
	else if (evt.charCode)
		return evt.charCode;
	return 0;
}

function key_pressdown(evt_p)
{
	try
	{
		var evt = login_get_cmd_kbd_event(evt_p);
		if(evt == null) return;
		var key_code = login_crack_kbd_event(evt);
		if(key_code == 0) return;
		// CR: Click login button
		if (key_code == 13)
		{
			elm_button.click();
			return false;
		}
	}
	catch (e)
	{
	}

	return true;
}

function update_token_msg(msg)
{
	while(elm_tokenmsg.childNodes.length)
	{
		elm_tokenmsg.removeChild(elm_tokenmsg.childNodes[0]);
	}

	var txt = document.createTextNode(msg);
	elm_tokenmsg.appendChild(txt);

	setTimeout("var elem = document.getElementById(\"token_msg\");", 100);
}

function showToken(show, token_type, token_info)
{
	var d = 'none'; //hide by default

	let is_fac_tfa_fortitoken = false;
	let is_ftm_push_enabled = false;
	if (show) d = '';
	if (elm_tokenmsg) {
		elm_tokenmsg.style.display = d;
		if (show) {
			switch (token_type) {
			case APS_TFA_FORTITOKEN_FAC_PUSH:
				is_ftm_push_enabled = true;
			case APS_TFA_FORTITOKEN_FAC:
				is_fac_tfa_fortitoken = true;
				// Token challenge from remote server.
				// falls through
			case APS_TFA_FORTITOKEN:
				if (token_type === APS_TFA_FORTITOKEN) {
					is_ftm_push_enabled = ftm_fgt_pushed_enabled;
				}
				elm_tokenmsg.style.display = 'none';
				break;
			case APS_TFA_DISABLE:
				// TFA disabled, but custom RADIUS challenge can get still here.
				// Show custom token message from RADIUS server.
				if (token_info) {
					update_token_msg(token_info);
				}
				break;
			case APS_TFA_EMAIL:
				update_token_msg(str_table.mail_token_msg + ' <' + token_info + '> ' + str_table.token_msg_rest);
				break;
			case APS_TFA_SMS:
				update_token_msg(str_table.sms_token_msg + ' <' + token_info + '> ' + str_table.token_msg_rest);
				break;
			}
			// Clear token code as there could be multiple token requests.
			elm_tokencode.value = "";
		}
	}
	if (elm_tokencode) elm_tokencode.style.display = d;
	if (elm_tokencode) elm_tokencode.disabled = show ? false : true;

	if (show && !token_push_request_in_progress && is_ftm_push_enabled) {
		trigger_ftm_push(is_fac_tfa_fortitoken);
	}

	elm_button.disabled = false;
}

function clear_input()
{
	var two_factor_auth = (!!document.getElementById("auth_two_factor"));

	if (!two_factor_auth) elm_username.value = "";
	elm_secretkey.value = "";
	elm_tokencode.value = "";
}

function abort_current_request() {
	my_xmlhttp.abort();
	delete my_xmlhttp;
	my_xmlhttp = null;
}

document.addEventListener('DOMContentLoaded', function() {
    var msg = getQueryValue(location.href, 'msg');
    if (msg) {
        update_warning_status_line(str_table[msg])
    }
});

if (elm_credentialContainer && elm_credentialContainer.classList.contains('hide-without-username')) {
	elm_loginButtonContainer.style.transition = 'max-height 0.8s ease-in-out';
	elm_credentialContainer.style.transition = 'max-height 0.8s ease-in-out';
	hidePassword();
	['click', 'keyup', 'change', 'paste'].forEach(eventName => {
		elm_username.addEventListener(eventName, event => {
			if (event.target.value || eventName === 'click') {
				showPassword();
			} else {
				hidePassword();
			}
		});
	});
	function showPassword() {
		if (elm_loginButtonContainer) {
			elm_loginButtonContainer.style.maxHeight = '300px';
		}
		if (elm_credentialContainer) {
			elm_credentialContainer.style.maxHeight = '300px';
		}
	}
	function hidePassword() {
		if (elm_loginButtonContainer) {
			elm_loginButtonContainer.style.maxHeight = '0';
			elm_loginButtonContainer.style.overflowY = 'hidden';
		}
		if (elm_credentialContainer) {
			elm_credentialContainer.style.maxHeight = '0';
			elm_credentialContainer.style.overflowY = 'hidden';
		}
		if (elm_secretkey) {
			elm_secretkey.value = '';
		}
	}
}
