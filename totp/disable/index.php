<?php

define("DVWA_WEB_PAGE_TO_ROOT", "../../");
require_once DVWA_WEB_PAGE_TO_ROOT . "dvwa/includes/dvwaPage.inc.php";

dvwaPageStartup(["authenticated"]);

$page = dvwaPageNewGrab();
$page["title"] = "TOTP: Disable" . $page["title_separator"] . $page["title"];
$page["page_id"] = "totp_d";
dvwaDatabaseConnect();

$user_session = dvwasessionGrab();

if (isset($_POST["totp_disable"])) {
    // Check Anti-CSRF token
    checkToken(
        $_REQUEST["user_token"],
        $_SESSION["session_token"],
        "index.php"
    );

    // Disable totp in the database
    $data = $db->prepare(
        "UPDATE users SET totp_enabled = 0,totp_secret=null WHERE user = (:user) LIMIT 1;"
    );
    $data->bindParam(":user", $user_session["username"], PDO::PARAM_STR);
    $data->execute();

    // Disable totp in the session
    dvwaTotpDisable();

    // Leave page
    dvwaRedirect(DVWA_WEB_PAGE_TO_ROOT . "index.php");
}

// Anti-CSRF
generateSessionToken();

$page["body"] .=
    "
<div class=\"body_padded\">

	<h1>Disable TOTP</h1>

    <form action=\"#\" method=\"post\">

        <input name=\"totp_disable\" type=\"submit\" value=\"Confirm\">
        
        " . tokenField() . "
        
        {$html}

    </form>

</div>";

dvwaHtmlEcho($page);
