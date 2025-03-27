<?php

// -------------------------- Utility Functions --------------------------
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

function curlGet($url) {
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

    return $response === false ? ["error" => $error ?: "Unknown cURL error"] : $response;
}

function getDNS($host) {
    return dns_get_record($host, DNS_ALL) ?: ["error" => "DNS resolution failed"];
}

function getOpenPorts($host) {
    $ports = [21,22,23,25,53,69,80,110,111,135,139,143,161,389,443,445,465,993,995,3306,3389,5432,5900,6379];
    $open = [];
    foreach ($ports as $port) {
        if (@fsockopen($host, $port, $errno, $errstr, 0.5)) {
            $open[] = $port;
        }
    }
    return $open;
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

function simplifyDNS($records) {
    $a = [];
    $aaaa = [];
    $filtered = [];
    foreach ($records as $r) {
        if ($r['type'] === 'A' && !in_array($r['ip'], $a)) {
            $a[] = $r['ip'];
            $filtered[] = $r;
        } elseif ($r['type'] === 'AAAA' && !in_array($r['ipv6'], $aaaa)) {
            $aaaa[] = $r['ipv6'];
            $filtered[] = $r;
        } elseif (!in_array($r, $filtered)) {
            $filtered[] = $r;
        }
    }
    return $filtered;
}

function truncateIfStringTooLong(&$data, $key, $label = "Truncated") {
    if (isset($data[$key]) && is_string($data[$key]) && strlen($data[$key]) > 1000) {
        $data[$key] = $label;
    }
}

function decodeJsonIfString(&$data, $key) {
    if (isset($data[$key]) && is_string($data[$key])) {
        $decoded = json_decode($data[$key], true);
        $data[$key] = json_last_error() === JSON_ERROR_NONE ? $decoded : "Could not parse JSON data";
    }
}

// -------------------------- MAIN SCAN EXECUTION --------------------------

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

[$headers, $html] = getHeadersAndHTML($url);
$dns = getDNS($host);
$ports = getOpenPorts($host);
$ssl = getSSLDetails($host);
$securityHeaders = getSecurityHeadersStatus($headers);
$cookies = getCookieData($headers);
$tech = ["PHP Scanner" => "Example only - Add detectTechStack if needed"];
$sql = ["status" => "stub - Add simulateSQLi function"];
$xss = ["status" => "stub - Add simulateXSS function"];
$shell = ["status" => "stub - Add simulateShellUpload function"];

$external = [];
$external['ssl_labs'] = curlGet("https://api.ssllabs.com/api/v3/analyze?host=$host");
$external['security_headers'] = curlGet("https://securityheaders.com/?q=https://$host&followRedirects=on");
$external['ipinfo'] = curlGet("https://ipinfo.io/$ip/json");
$shodanKey = "SHODAN_API_KEY";
$external['shodan'] = curlGet("https://api.shodan.io/shodan/host/$ip?key=$shodanKey");

$end = endTimer($start);

// Cleanup output
$dns = simplifyDNS($dns);
truncateIfStringTooLong($external, "ssl_labs");
truncateIfStringTooLong($external, "security_headers");
decodeJsonIfString($external, "ipinfo");
decodeJsonIfString($external, "shodan");

header('Content-Type: application/json');
echo json_encode([
    "meta" => array_merge([
        "scan_target" => $url,
        "host" => $host,
        "ip" => $ip
    ], $end),
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
    "xss_test" => $xss,
    "remote_shell_upload_test" => $shell,
    "external" => $external
], JSON_PRETTY_PRINT);
