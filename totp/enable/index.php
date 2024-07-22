<?php

define( 'DVWA_WEB_PAGE_TO_ROOT', '../../' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaPageStartup( array( 'authenticated' ) );

$page = dvwaPageNewGrab();
$page[ 'title' ]   = 'TOTP: Enable' . $page[ 'title_separator' ].$page[ 'title' ];
$page[ 'page_id' ] = 'totp_e';

dvwaDatabaseConnect();

//include packages for composer
require '../../vendor/autoload.php';

use PragmaRX\Google2FA\Google2FA;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\Image\ImagickImageBackEnd;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;

$_g2fa = new Google2FA();

// Generate a secret key and a test user

$user_totp = dvwasessionGrab();
if( !isset( $_POST[ 'totp_enable' ] ) ){
   $user_totp['totp_secret'] = $_g2fa->generateSecretKey();
   $_SESSION['g2fa_user'] = $user_totp;

   // Generate a custom URL from user data to provide to qr code generator
   $qrCodeUrl = $_g2fa->getQRCodeUrl(
     'dvwa',
   $user_totp['username'],
   $user_totp['totp_secret']
   );

  // QR Code Generation using bacon/bacon-qr-code
  // Set up image rendered and writer
  $renderer = new ImageRenderer(
    new RendererStyle(250),
    new ImagickImageBackEnd()
  );
  $writer = new Writer($renderer);

  // This option is to store the QR Code image in the server
  $writer->writeFile($qrCodeUrl, 'qrcode.png');

  // This option will create a string with the image data and base64 enconde it
  $encoded_qr_data = base64_encode($writer->writeString($qrCodeUrl));

  // This will provide us with the current password
  $current_otp = $_g2fa->getCurrentOtp($user_totp['totp_secret']);
 
}else
{
 $encoded_qr_data = "";
 $qrCodeUrl = "";
 $current_otp = "";
}

if( isset( $_POST[ 'totp_enable' ] ) ) {
        // Check Anti-CSRF token
        checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

        // Sanitise username input
        $user = $_SESSION['g2fa_user'][ 'username' ];
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
		$otp = $_POST['otp'];
		$otp = stripslashes( $otp );
		$_g2fa_verify = new Google2FA();
		
		$valid = $_g2fa_verify->verifyKey($_SESSION['g2fa_user']['totp_secret'], $otp);
		
		if($valid){
		$data = $db->prepare( 'UPDATE users SET totp_enabled = "1", totp_secret = (:totp_secret) WHERE user = (:user) LIMIT 1;' );
                $data->bindParam( ':totp_secret', $_SESSION['g2fa_user']['totp_secret'], PDO::PARAM_STR );
                $data->bindParam( ':user', $user, PDO::PARAM_STR );     
		$data->execute();
                dvwaTotpEnable();

                // Leave page
                dvwaRedirect( DVWA_WEB_PAGE_TO_ROOT . 'index.php' );

		}
		

               $html .= "<pre><br />Code incorrect.<br /></pre>";
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
        <p><img src=\"data:image/png;base64, $encoded_qr_data \" alt=\"QR Code\"></p>
        <p> QR code URL: $qrCodeUrl</p>
        <p>One-time password at time of generation:  $current_otp </p>
        <!-- Create db button -->
        <form action=\"#\" method=\"post\">
               Generate then enter code:<br />
                <input type=\"text\" name=\"otp\"><br />
                Verify your password:<br />
                <input type=\"password\" AUTOCOMPLETE=\"off\" name=\"password\"><br />
		<br />
                <input name=\"totp_enable\" type=\"submit\" value=\"Confirm\">
                " . tokenField() . "
{$html}
        </form>
</div>";

dvwaHtmlEcho( $page );

?>
