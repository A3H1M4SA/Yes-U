<?php
function collectWebsiteData($url) {
    $parsed = parse_url($url);
    $host = $parsed['host'] ?? $url;
    $ip = gethostbyname($host);
    $dnsRecords = dns_get_record($host, DNS_ALL);

    $ping = shell_exec("ping -c 2 " . escapeshellarg($host));
    preg_match("/time=(.*?) ms/", $ping, $latency);
    $latency = $latency[1] ?? 'N/A';

    $ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306];
    $openPorts = [];
    foreach ($ports as $port) {
        $conn = @fsockopen($host, $port, $errno, $errstr, 0.5);
        if ($conn) {
            $openPorts[] = $port;
            fclose($conn);
        }
    }

    $sslInfo = [];
    $context = stream_context_create(["ssl" => ["capture_peer_cert" => true]]);
    $client = @stream_socket_client("ssl://$host:443", $errno, $errstr, 1.5, STREAM_CLIENT_CONNECT, $context);
    if ($client) {
        $cont = stream_context_get_params($client);
        $cert = openssl_x509_parse($cont["options"]["ssl"]["peer_certificate"]);
        $sslInfo = [
            "issuer" => $cert['issuer']['CN'] ?? '',
            "validFrom" => date('Y-m-d', $cert['validFrom_time_t']),
            "validTo" => date('Y-m-d', $cert['validTo_time_t']),
        ];
    }

    $headers = @get_headers($url, 1);

    $paths = ["/robots.txt", "/.git/", "/.env"];
    $exposed = [];
    foreach ($paths as $path) {
        $check = @get_headers($url . $path, 1);
        if ($check && strpos($check[0], "200") !== false) {
            $exposed[] = $path;
        }
    }

    $homepage = @file_get_contents($url);

    return [
        "url" => $url,
        "ip" => $ip,
        "dns_records" => $dnsRecords,
        "latency_ms" => $latency,
        "open_ports" => $openPorts,
        "ssl_info" => $sslInfo,
        "headers" => $headers,
        "exposed_files" => $exposed,
        "html_snippet" => substr($homepage, 0, 1000)
    ];
}

if (isset($_GET['url'])) {
    $data = collectWebsiteData($_GET['url']);
    echo "<h2>Scan Results for: {$data['url']}</h2>";
    echo "<pre>" . json_encode($data, JSON_PRETTY_PRINT) . "</pre>";
} else {
    echo "No URL provided.";
}
