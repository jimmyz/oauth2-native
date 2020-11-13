<?php
$client_id = 'a023Z00000bVNbgQAG';
$auth_path = 'https://identint.familysearch.org/cis-web/oauth2/v3/authorization';
$token_path = 'https://identint.familysearch.org/cis-web/oauth2/v3/token';

$ip = '127.0.0.1';
$port = '52321';

$redirect_uri = 'http://'.$ip.':'.$port.'/familysearch-auth';
echo "Make sure you have registered redirect URI: ".$redirect_uri."\n";
$socket_str = 'tcp://'.$ip.':'.$port;
$state = bin2hex(random_bytes(5));


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
  // hash function should return raw bytes
  return encode_string(hash("sha256",$v,true));
}


$verifier = create_verifier();
$challenge = create_challenge($verifier);

echo "Verifier: ".$verifier."\n";
echo "Challenge: ".$challenge."\n";

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
shell_exec("open '".$authorize_url."'");


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
      $body    = null;
      $content_length = 0;
      //read request headers
      while(false !== ($line = trim(fgets($sock)))) {
        echo $line."\n";
        if('' === $line) {
          echo "End of headers detected.\n";
          break;
        }
        $regex = '#^Content-Length:\s*([[:digit:]]+)\s*$#i';
        if(preg_match($regex, $line, $matches)) {
          $content_length = (int)$matches[1];
        }
        $headers[] = $line;
      }
      // Debugging, print all of the headers
      echo "\$headers[] :\n";
      print_r($headers);

      // read content/body
      if($content_length > 0) {
        $body = fread($sock, $content_length);
      } else {
        echo "No content body.\n";
      }
      // send response
      list($method, $url, $httpver) = explode(' ', $headers[0]);
      if($method == 'GET') {
        #echo "Redirected to $url\n";
        $parts = parse_url($url);
        #print_r($parts);
        if(isset($parts['path']) && $parts['path'] == '/familysearch-auth'
          && isset($parts['query'])
        ) {
          parse_str($parts['query'], $query);
          if(isset($query['code']) && isset($query['state'])) {
            fwrite($sock, $responseOk);
            fclose($sock);
            return $query;
          }
        }
      }
      fwrite($sock, $responseErr);
      fclose($sock);
    } while (true);
  }

// Start the mini HTTP server and wait for their browser to hit the redirect URL
// Store the query string parameters in a variable
$auth = startHttpServer($socket_str);

if($auth['state'] != $state) {
  echo "Wrong 'state' parameter returned\n";
  exit(2);
}

$code = $auth['code'];
echo "Auth code is: ".$code."\n";

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