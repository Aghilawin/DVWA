<?php

define("DVWA_WEB_PAGE_TO_ROOT", "../../");
require_once DVWA_WEB_PAGE_TO_ROOT . "dvwa/includes/dvwaPage.inc.php";

dvwaPageStartup(["authenticated"]);

$page = dvwaPageNewGrab();
$page["title"] = "TOTP: Enable" . $page["title_separator"] . $page["title"];
$page["page_id"] = "totp_e";

dvwaDatabaseConnect();

require "../../vendor/autoload.php";

// Load totp libraries using composer

use PragmaRX\Google2FA\Google2FA;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\Image\ImagickImageBackEnd;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;

$_g2fa = new Google2FA();

// Generate a secret key for the user

$user_session = dvwasessionGrab();
$user_session["totp_secret"] = $_g2fa->generateSecretKey();

if (!isset($_POST["totp_enable"])) {

    $_SESSION["g2fa_user"] = $user_session;

    // Generate a custom URL from user data to provide to qr code generator
    $qrCodeUrl = $_g2fa->getQRCodeUrl(
        "dvwa",
        $user_session["username"],
        $user_session["totp_secret"]
    );
    $_SESSION["qrCodeUrl"] = $qrCodeUrl;

    // QR Code Generation using bacon/bacon-qr-code

    // Set up image rendered and writer
    $renderer = new ImageRenderer(
        new RendererStyle(250),
        new ImagickImageBackEnd()
    );
    $writer = new Writer($renderer);

    // This option is to store the QR Code image in the server
    $writer->WriteFile($qrCodeUrl, "totp/enable/qrcode.png");

    // This option will create a string with the image data and base64 enconde it
    $encoded_qr_data = base64_encode($writer->writeString($qrCodeUrl));
    $_SESSION["qrdata"] = $encoded_qr_data;
} else {
    // Handle the request from the user entering the code

    // Get the QR data from before the user entered the generated code
    $encoded_qr_data = $_SESSION["qrdata"];
    $qrCodeUrl = $_SESSION["qrCodeUrl"];

    // Get users details
    $otp = $_POST["otp"];
    $otp = stripslashes($otp);
    $_g2fa = new Google2FA();

    // Verify provided OTP (Will return true or false)
    $valid = $_g2fa->verifyKey(
        $_SESSION["g2fa_user"]["totp_secret"],
        $otp
    );

    if ($valid) {
        // Enable totp in the database and save the secret for the user
        $data = $db->prepare(
            'UPDATE users SET totp_enabled = "1", totp_secret = (:totp_secret) WHERE user = (:user) LIMIT 1;'
        );
        $data->bindParam(
            ":totp_secret",
            $_SESSION["g2fa_user"]["totp_secret"],
            PDO::PARAM_STR
        );
        $data->bindParam(":user", $user_session["username"], PDO::PARAM_STR);
        $data->execute();

        // Enable totp in the session
        dvwaTotpEnable();

        // Leave page
        dvwaRedirect(DVWA_WEB_PAGE_TO_ROOT . "index.php");
    }

    $html .= "<pre><br />Code incorrect.<br /></pre>";
}

// Anti-CSRF
generateSessionToken();

$page["body"] .=
    "
<div class=\"body_padded\">

	<h1>Enable TOTP</h1>

    <p><img src=\"data:image/png;base64, $encoded_qr_data \" alt=\"QR Code\"></p>

    <p> QR code URL: $qrCodeUrl</p>
   
    <form action=\"#\" method=\"post\">

        Generate then enter code:<br />

        <input type=\"text\" name=\"otp\"><br />

	    <br />

        <input name=\"totp_enable\" type=\"submit\" value=\"Confirm\">

        " . tokenField() . "

        {$html}
        
        </form>

</div>";

dvwaHtmlEcho($page);
