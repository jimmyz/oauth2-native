<?php
// This script is adapted from the excellent tutorial provided by Aaron Parecki (Okta)
// https://developer.okta.com/blog/2018/07/16/oauth-2-command-line

$client_id = 'a023Z00000bVNbgQAG';
$auth_path = 'https://identint.familysearch.org/cis-web/oauth2/v3/authorization';
$token_path = 'https://identint.familysearch.org/cis-web/oauth2/v3/token';

$ip = '127.0.0.1';
$port = '52321';

// Set the Redirect URI. This will need to be registered with FamilySearch
$redirect_uri = 'http://'.$ip.':'.$port;
echo "Make sure you have registered Redirect URI: ".$redirect_uri."\n";

// This is the string that will be used to open up a socket to listen on the specified port
$socket_str = 'tcp://'.$ip.':'.$port;

// This will be used later in the OAuth protocol as a security mechanism
$state = bin2hex(random_bytes(5));

// The following are functions used to create the Code Challenge and Verifier for PKCE
function encode_string($bytes) {
  $vstring = base64_encode($bytes);
  $vstring = str_replace("+","-",$vstring);
  $vstring = str_replace("/","_",$vstring);
  $vstring = str_replace("=","",$vstring);
  return $vstring;
}

function create_verifier() {
  return encode_string(random_bytes(32));
}

function create_challenge($v) {
  return encode_string(hash("sha256",$v,true));
}

// Create the Code Challenge and Verifier for PKCE
$verifier = create_verifier();
$challenge = create_challenge($verifier);

echo "Verifier: ".$verifier."\n";
echo "Challenge: ".$challenge."\n";

// Create the Authorization URL. 
// This is the URL to be used in the user's browser for authenticating and granting consent.
$authorize_url = $auth_path.'?'.http_build_query([
  'client_id' => $client_id,
  'redirect_uri' => $redirect_uri,
  'response_type' => 'code',
  'state' => $state,
  'scope' => 'openid',
  'code_challenge' => $challenge,
  'code_challenge_method' => 'S256'
]);

echo "Open the following URL in a browser to continue\n";
echo $authorize_url."\n";
// Attempt to launch the browser with the Authorize URL location.
// This is verified to work on Mac. Unsure about Windows or Linux.
shell_exec("open '".$authorize_url."'");

// The following function handles the listening on the loopback address for the redirect.
function startHttpServer($socketStr) {
    // Adapted from http://cweiske.de/shpub.htm
  
    $responseOk = "HTTP/1.0 200 OK\r\n"
      . "Content-Type: text/plain\r\n"
      . "\r\n"
      . "Ok. You may close this tab and return to the shell.\r\n";
    $responseErr = "HTTP/1.0 400 Bad Request\r\n"
      . "Content-Type: text/plain\r\n"
      . "\r\n"
      . "Bad Request\r\n";

    ini_set('default_socket_timeout', 60 * 5);
  
    $server = stream_socket_server($socketStr, $errno, $errstr);

    echo "Listening on ".$socketStr."...\n";
    if(!$server) {
      echo 'Error starting HTTP server';
      return false;
    }
  
    do {
      $sock = stream_socket_accept($server);
      if(!$sock) {
        echo "Error accepting socket connection";
        exit(1);
      }
      $headers = [];

      // Capture the HTTP request. 
      // Each header is delimited by newline. 
      // Headers end with the empty string.
      while(false !== ($line = trim(fgets($sock)))) {
        if('' === $line) {
          // End of headers has been reached. Break from listening
          break;
        }
        $headers[] = $line;
      }
      // Debug print all of the request headers.
      echo "\$headers[] :\n";
      print_r($headers);

      // Break up first line of HTTP request into the method, URL, and version
      // $header[0] contains the first line of HTTP request. This part is all that is needed.
      // Example: GET /?code=-35-8469...&state=1c8cca364c HTTP/1.1
      // Each part is separated by a space character
      list($method, $url, $httpver) = explode(' ', $headers[0]);
      if($method == 'GET') {
        $parts = parse_url($url);
        if(isset($parts['query'])) {
          parse_str($parts['query'], $query);
          if(isset($query['code']) && isset($query['state'])) {
            // Send success response to the browser
            fwrite($sock, $responseOk);
            fclose($sock);
            return $query;
          }
        }
      }
      // Send error response to browser if above checks failed
      fwrite($sock, $responseErr);
      fclose($sock);
    } while (true);
  }

// Start the mini HTTP server and wait for their browser to hit the redirect URL
// Return the query string parameters in the $auth variable
$auth = startHttpServer($socket_str); // tcp://127.0.0.1:23424

// Check to make sure state returned matches the state we passed on the Authorization URL
if($auth['state'] != $state) {
  echo "Wrong 'state' parameter returned\n";
  exit(2);
}

// Get the auth code to be exchanged for tokens
$code = $auth['code'];
echo "Auth code is: ".$code."\n";

// This function executes an HTTP request to the token endpoint. 
// Returns an associative array containing tokens or error.
function token_request($url, $params) {
  $curl = curl_init();
  $request_body = http_build_query($params);

  curl_setopt_array($curl, array(
    CURLOPT_URL => $url,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_ENCODING => "",
    CURLOPT_MAXREDIRS => 10,
    CURLOPT_TIMEOUT => 0,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    CURLOPT_CUSTOMREQUEST => "POST",
    CURLOPT_POSTFIELDS => $request_body,
    CURLOPT_HTTPHEADER => array(
      "Content-Type: application/x-www-form-urlencoded"
    ),
  ));

  $tokens = json_decode(curl_exec($curl));

  curl_close($curl);
  return $tokens;
}

echo "Getting an access token...\n";
$response = token_request($token_path, [
  'grant_type' => 'authorization_code',
  'code' => $code,
  'redirect_uri' => $redirect_uri,
  'client_id' => $client_id,
  'code_verifier' => $verifier
]);

if(!isset($response->access_token)) {
  echo "Error fetching access token\n";
  exit(2);
}

$access_token = $response->access_token;
echo "Tokens:\n";
print_r($response);
echo "\n".$access_token."\n";

?>