<?php
define("DVWA_WEB_PAGE_TO_ROOT", "");
require_once DVWA_WEB_PAGE_TO_ROOT . "dvwa/includes/dvwaPage.inc.php";

session_start();

// Display All Errors (For Easier Development)
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ALL);

require "./vendor/autoload.php";

use PragmaRX\Google2FA\Google2FA;

dvwaPageStartup([]);

dvwaDatabaseConnect();

if (isset($_POST["verify"])) {
	$_g2fa = new Google2FA();
	$key = $_SESSION["secret"];
	$otp = $_POST["code"];

	// Verify provided OTP (Will return true or false)
	$valid = $_g2fa->verifyKey($key, $otp);

	if ($valid) {
		dvwalogin($_SESSION["g2fa_user"]);
		dvwaRedirect("index.php");
	} else {
		dvwaMessagePush("Login failed");
		dvwaRedirect("login.php");
	}
}

$messagesHtml = messagesPopAllToHtml();

Header("Cache-Control: no-cache, must-revalidate"); // HTTP/1.1
Header("Content-Type: text/html;charset=utf-8"); // TODO- proper XHTML headers...
Header("Expires: Tue, 23 Jun 2009 12:00:00 GMT"); // Date in the past

// Anti-CSRF
generateSessionToken();

echo "<!DOCTYPE html>

<html lang=\"en-GB\">

	<head>

		<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />

		<title>Login :: Damn Vulnerable Web Application (DVWA)</title>

		<link rel=\"stylesheet\" type=\"text/css\" href=\"" .
	DVWA_WEB_PAGE_TO_ROOT .
	"dvwa/css/login.css\" />

	</head>

	<body>

	<div id=\"wrapper\">

	<div id=\"header\">

	<br />

	<p><img src=\"" .
	DVWA_WEB_PAGE_TO_ROOT .
	"dvwa/images/login_logo.png\" /></p>

	<br />

	</div> <!--<div id=\"header\">-->

	<div id=\"content\">

	<form action=\"verify_totp.php\" method=\"post\">

	<fieldset>

		<label for=\"user\">Enter Code</label> <input type=\"text\" class=\"loginInput\" size=\"20\" name=\"code\"><br />

		<br />

		<p class=\"submit\"><input type=\"submit\" value=\"verify\" name=\"verify\"></p>

	</fieldset>

	" . tokenField() . "

	</form>

	<br />

	{$messagesHtml}

	<br />
	<br />
	<br />
	<br />
	<br />
	<br />
	<br />
	<br />

	</div > <!--<div id=\"content\">-->

	<div id=\"footer\">

	<p>" .
	dvwaExternalLinkUrlGet(
		"https://github.com/digininja/DVWA/",
		"Damn Vulnerable Web Application (DVWA)"
	) .
	"</p>

	</div> <!--<div id=\"footer\"> -->

	</div> <!--<div id=\"wrapper\"> -->

	</body>

</html>";
