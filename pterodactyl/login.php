<?php
$env = parse_ini_file('.env');

use WHMCS\Carbon;
use WHMCS\Cookie;

define("CLIENTAREA",true);

require("../../../init.php");

$ca = new WHMCS_ClientArea();
$ca->requireLogin();

// sets userid for the logged in user. Is set to 0 if no one is logged in.
$userid = $ca->getUserID() ;
 
// sets loggedin to true if logged in, and false if not logged in.
If ($userid > 0) { $loggedin = true; }
else { $loggedin = false; }

if (!$loggedin) {
    die();
}


function base64UrlEncode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-'), '=');
}

$secretKey = $env["SSO_Token"]; 
$header = json_encode(["alg" => "HS256", "typ" => "JWT"]);
$payload = json_encode([
    "user" => [
        "id" => $env["SSO_Ident"]."-".$userid
    ],
    "iat" => time(),
    "exp" => time() + 60 // Token expires in 1 hour
]);

$base64UrlHeader = base64UrlEncode($header);
$base64UrlPayload = base64UrlEncode($payload);

$signature = hash_hmac('sha256', "$base64UrlHeader.$base64UrlPayload", $secretKey, true);
$base64UrlSignature = base64UrlEncode($signature);

$jwtToken = "$base64UrlHeader.$base64UrlPayload.$base64UrlSignature";

$ssoUrl = $env["SSO_URL"]; 
if($_GET['r']){ $url = urldecode($_GET['r']); }
?>


<!DOCTYPE html>
<html lang="da">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSO Login</title>
</head>
<body>
    <form id="ssoForm" name="ssoForm" action="<?php echo htmlspecialchars($ssoUrl); ?>" method="POST">
        <input type="hidden" name="pteroca_sso_token" value="<?php echo urlencode($jwtToken); ?>">
       <?php if($url){ ?>  <input type="hidden" name="pteroca_sso_redirect" value="<?php echo $url; ?>"><?php } ?>

        <button type="submit" hidden>Login med SSO</button>
    </form>

    <script type="text/javascript">
    document.ssoForm.submit();
</script>
</body>
</html>