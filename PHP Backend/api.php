<?php

function startTimer() {
    return microtime(true);
}

function endTimer($start) {
    $end = microtime(true);
    return [
        "start_time" => date("Y-m-d H:i:s", (int)$start),
        "end_time" => date("Y-m-d H:i:s", (int)$end),
        "duration_seconds" => round($end - $start, 2)
    ];
}

function curlGet($url, $asJson = false) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_USERAGENT => "Mozilla/5.0",
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_TIMEOUT => 10,
    ]);
    $response = curl_exec($ch);
    $error = curl_error($ch);
    curl_close($ch);

    if ($response === false) {
        return ["error" => $error ?: "Unknown cURL error"];
    }

    return $asJson ? json_decode($response, true) : $response;
}

function getOpenPorts($host) {
    $ports = [21,22,23,25,53,80,110,143,443,3306,3389,5900];
    $open = [];
    foreach ($ports as $port) {
        if (@fsockopen($host, $port, $errno, $errstr, 0.5)) {
            $open[] = $port;
        }
    }
    return $open;
}

function simulateSQLi($url) {
    $testUrl = rtrim($url, '/') . "/?id=' OR '1'='1";
    $res = curlGet($testUrl);
    if (isset($res['error'])) return ["status" => "error", "message" => $res['error']];
    $flags = ['sql', 'syntax', 'mysql', 'ORA-', 'ODBC'];
    foreach ($flags as $f) {
        if (stripos($res, $f) !== false) return ["status" => "potential", "indicator" => $f];
    }
    return ["status" => "clean"];
}

function getDNS($host) {
    return dns_get_record($host, DNS_ALL) ?: ["error" => "DNS resolution failed"];
}

function getSSLDetails($host) {
    $context = stream_context_create(["ssl" => ["capture_peer_cert" => true]]);
    $client = @stream_socket_client("ssl://$host:443", $errno, $errstr, 3, STREAM_CLIENT_CONNECT, $context);
    if (!$client) return ["error" => "SSL handshake failed: $errstr"];
    $params = stream_context_get_params($client);
    $cert = openssl_x509_parse($params["options"]["ssl"]["peer_certificate"]);
    return [
        "issuer" => $cert["issuer"]["CN"] ?? "",
        "subject" => $cert["subject"]["CN"] ?? "",
        "valid_from" => date("Y-m-d", $cert["validFrom_time_t"] ?? 0),
        "valid_to" => date("Y-m-d", $cert["validTo_time_t"] ?? 0),
        "serial" => $cert["serialNumberHex"] ?? "",
        "signature" => $cert["signatureTypeSN"] ?? "",
        "self_signed" => ($cert["issuer"]["CN"] ?? "") === ($cert["subject"]["CN"] ?? "")
    ];
}

function detectTechStack($html) {
    if (!is_string($html)) return [];
    $tech = [];
    if (stripos($html, 'wp-content') !== false) $tech[] = "WordPress";
    if (stripos($html, 'jquery') !== false) $tech[] = "jQuery";
    if (stripos($html, 'bootstrap') !== false) $tech[] = "Bootstrap";
    if (stripos($html, 'react') !== false) $tech[] = "React.js";
    if (stripos($html, 'vue') !== false) $tech[] = "Vue.js";
    if (stripos($html, 'cdn.jsdelivr') !== false) $tech[] = "JSDelivr CDN";
    if (stripos($html, 'fontawesome') !== false) $tech[] = "FontAwesome";
    return $tech;
}

function getHeadersAndHTML($url) {
    $context = stream_context_create([
        'http' => ['method' => "GET", 'header' => "User-Agent: Mozilla/5.0\r\n"]
    ]);
    $headers = @get_headers($url, 1, $context);
    $html = @file_get_contents($url, false, $context);
    return [$headers ?: ["error" => "Headers could not be fetched"], $html ?: "Homepage HTML could not be fetched"];
}

function getCookieData($headers) {
    if (!$headers || isset($headers['error'])) return [["error" => "No Set-Cookie headers or headers not fetched"]];
    $cookies = isset($headers['Set-Cookie']) ? (array)$headers['Set-Cookie'] : [];
    $info = [];
    foreach ($cookies as $cookie) {
        $info[] = [
            "raw" => $cookie,
            "flags" => [
                "HttpOnly" => stripos($cookie, 'httponly') !== false,
                "Secure" => stripos($cookie, 'secure') !== false,
                "SameSite" => stripos($cookie, 'samesite') !== false
            ]
        ];
    }
    return $info;
}

function getSecurityHeadersStatus($headers) {
    $required = [
        "referrer-policy", "x-content-type-options",
        "strict-transport-security", "content-security-policy", "x-frame-options"
    ];
    $status = [];
    $headers = array_change_key_case($headers, CASE_LOWER);
    foreach ($required as $header) {
        $status[$header] = isset($headers[$header]);
    }
    return $status;
}

// MAIN
if (!isset($_GET['url'])) {
    header('Content-Type: application/json');
    echo json_encode(["error" => "Missing ?url parameter"]);
    exit;
}

$url = $_GET['url'];
$parsed = parse_url($url);
$host = $parsed['host'] ?? $url;
$ip = gethostbyname($host);
$start = startTimer();

$dns = getDNS($host);
$ports = getOpenPorts($host);
$ssl = getSSLDetails($host);
[$headers, $html] = getHeadersAndHTML($url);
$securityHeaders = getSecurityHeadersStatus($headers);
$cookies = getCookieData($headers);
$tech = detectTechStack($html);
$sql = simulateSQLi($url);

// 🌐 External API integrations
$external = [];

$external['ssl_labs'] = curlGet("https://api.ssllabs.com/api/v3/analyze?host=$host", true);
$external['security_headers'] = curlGet("https://securityheaders.com/?q=https://$host&followRedirects=on");
$external['ipinfo'] = curlGet("https://ipinfo.io/$ip/json", true);
$shodanKey = "h9YmSewS9IaS3mE9WufnBhNPH4v9Txav";
$external['shodan'] = curlGet("https://api.shodan.io/shodan/host/$ip?key=$shodanKey", true);

$end = endTimer($start);

// FINAL OUTPUT
// FINAL OUTPUT
header('Content-Type: application/json');
header('Content-Disposition: attachment; filename="output.json"');
echo json_encode([

    "meta" => [
        "scan_target" => $url,
        "host" => $host,
        "ip" => $ip,
        "start_time" => $end["start_time"],
        "end_time" => $end["end_time"],
        "duration_seconds" => $end["duration_seconds"]
    ],
    "network" => [
        "dns_records" => $dns,
        "open_ports" => $ports
    ],
    "ssl_certificate" => $ssl,
    "http" => [
        "raw_headers" => $headers,
        "security_headers" => $securityHeaders,
        "homepage_html_snippet" => is_string($html) ? substr($html, 0, 2000) : $html
    ],
    "cookies" => $cookies,
    "technologies_detected" => $tech,
    "sql_injection_test" => $sql,
    "external" => $external
], JSON_PRETTY_PRINT);
