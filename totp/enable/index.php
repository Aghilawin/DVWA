<?php

define( 'DVWA_WEB_PAGE_TO_ROOT', '../../' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaPageStartup( array( 'authenticated' ) );

$page = dvwaPageNewGrab();
$page[ 'title' ]   = 'TOTP: Enable' . $page[ 'title_separator' ].$page[ 'title' ];
$page[ 'page_id' ] = 'totp_e';
dvwaDatabaseConnect();

if( isset( $_POST[ 'totp_enable' ] ) ) {
	// Check Anti-CSRF token
        checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

	// Sanitise username input
        $user = $_POST[ 'username' ];
        $user = stripslashes( $user );
        $user = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $user ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

        // Sanitise password input
        $pass = $_POST[ 'password' ];
        $pass = stripslashes( $pass );
        $pass = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
        $pass = md5( $pass );

	// Check the database (if username matches the password)
        $data = $db->prepare( 'SELECT * FROM users WHERE user = (:user) AND password = (:password) LIMIT 1;' );
        $data->bindParam( ':user', $user, PDO::PARAM_STR);
        $data->bindParam( ':password', $pass, PDO::PARAM_STR );
        $data->execute();
        $row = $data->fetch();

        // If it's valid authentication...
        if( ( $data->rowCount() == 1 )) {
                // Get users details
                $totp_enabled       = $row[ 'totp_enabled' ];

                // Enable totp in the database
                $data = $db->prepare( 'UPDATE users SET totp_enabled = "1" WHERE user = (:user) LIMIT 1;' );
                $data->bindParam( ':user', $user, PDO::PARAM_STR );
                $data->execute();

		// Enable totp in the session
                dvwaTotpEnable();

		// Leave page
		dvwaRedirect( DVWA_WEB_PAGE_TO_ROOT . 'index.php' );
        } else {
                // Authentication failed

                // Give the user some feedback
                $html .= "<pre><br />Username and/or password incorrect.<br /></pre>";
        }

}

// Anti-CSRF
generateSessionToken();

$page[ 'body' ] .= "
<div class=\"body_padded\">
	<h1>Enable TOTP</h1>

        <!-- Create db button -->
        <form action=\"#\" method=\"post\">
		Username:<br />
                <input type=\"text\" name=\"username\"><br />
                Password:<br />
                <input type=\"password\" AUTOCOMPLETE=\"off\" name=\"password\"><br />
                <br />

                <input name=\"totp_enable\" type=\"submit\" value=\"Confirm\">
		" . tokenField() . "
		{$html}
        </form>
</div>";

dvwaHtmlEcho( $page );

?>
