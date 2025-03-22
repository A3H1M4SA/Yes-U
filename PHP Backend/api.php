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

function curlGet($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5); // 5 second timeout
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3); // 3 second connection timeout
    
    $response = curl_exec($ch);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error) {
        return ['error' => $error];
    }
    
    return $response;
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

function simulateSQLi($url) {
    $payloads = [
        "' OR '1'='1", "' OR 1=1--", "'; WAITFOR DELAY '0:0:5'--",
        "' AND sleep(5)--", "\" OR \"\" = \"", "' OR '' = '",
        "' OR 'a' = 'a", "' AND 1=0 UNION SELECT null--"
    ];
    $results = [];
    foreach ($payloads as $payload) {
        $testUrl = rtrim($url, '/') . "/?id=" . urlencode($payload);
        $res = curlGet($testUrl);
        $match = false;
        if (isset($res['error'])) {
            $results[] = ["payload" => $payload, "result" => "error", "message" => $res['error']];
            continue;
        }
        $flags = ['sql', 'syntax', 'mysql', 'ORA-', 'ODBC', 'error'];
        foreach ($flags as $f) {
            if (stripos($res, $f) !== false) {
                $match = true;
                break;
            }
        }
        $results[] = ["payload" => $payload, "result" => $match ? "potential vulnerability" : "clean"];
    }
    return $results;
}

function simulateXSS($url) {
    // Simple test payloads that won't cause PHP parsing issues
    $testPayloads = [
        "xss'test",
        "xss\"test",
        "<script>test</script>",
        "<img src=x onerror=test>",
        "javascript:test",
        "';alert(1);'",
        "\";alert(1);\"",
        "</script><script>test</script>",
        "<a href=\"javascript:test\">click</a>"
    ];

    $results = [];
    $commonParameters = ['q', 'search', 'query', 'id', 'page'];
    
    // Very limited testing to prevent timeout
    $maxTests = 3; // Only test 3 payloads
    $testCount = 0;

    foreach ($testPayloads as $payload) {
        if ($testCount >= $maxTests) {
            break;
        }
        $testCount++;
        
        $findings = [];
        
        // Only test 2 parameters to prevent timeout
        $limitedParams = array_slice($commonParameters, 0, 2);
        foreach ($limitedParams as $param) {
            // URL Parameter Test
            $testUrl = rtrim($url, '/') . "/?" . $param . "=" . urlencode($payload);
            $res = curlGet($testUrl);
            
            if (is_array($res) && isset($res['error'])) {
                $findings[] = [
                    "injection_point" => "url_param_" . $param,
                    "status" => "error",
                    "message" => $res['error']
                ];
                continue;
            }

            // Simple reflection check
            $reflected = (stripos($res, $payload) !== false);
            $sanitized = false;
            
            // Check if potentially sanitized
            if (stripos($res, strip_tags($payload)) !== false) {
                $sanitized = true;
            }

            // Very simple execution check
            $executionPossible = false;
            if ($reflected && !$sanitized && (
                stripos($res, "<script") !== false || 
                stripos($res, "javascript:") !== false ||
                stripos($res, "onerror") !== false
            )) {
                $executionPossible = true;
            }

            $findings[] = [
                "injection_point" => "url_param_" . $param,
                "payload" => $payload,
                "reflected" => $reflected,
                "sanitized" => $sanitized,
                "execution_possible" => $executionPossible
            ];
        }

        $results[] = [
            "payload" => $payload,
            "findings" => $findings,
            "overall_risk" => calculateXSSRisk($findings)
        ];
    }

    return $results;
}

function calculateXSSRisk($findings) {
    $riskScore = 0;
    $totalTests = count($findings);
    
    if ($totalTests == 0) {
        return "Unknown";
    }
    
    foreach ($findings as $finding) {
        if ($finding['reflected'] && !$finding['sanitized']) {
            $riskScore += 1;
            
            if (isset($finding['execution_possible']) && $finding['execution_possible']) {
                $riskScore += 2;
            }
        }
    }
    
    $normalizedScore = $riskScore / $totalTests;
    
    if ($normalizedScore >= 2) {
        return "High";
    } else if ($normalizedScore >= 0.5) {
        return "Medium";
    } else if ($normalizedScore > 0) {
        return "Low";
    } else {
        return "None";
    }
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

function detectTechStack($html, $headers = []) {
    if (!is_string($html)) return [];
    $tech = [];
    
    // CMS Detection
    $cmsPatterns = [
        'WordPress' => ['wp-content', 'wp-includes', 'wp-json'],
        'Drupal' => ['drupal.js', 'drupal.min.js', 'sites/all/themes', 'sites/default'],
        'Joomla' => ['joomla', 'com_content', 'com_users', '/administrator'],
        'Magento' => ['magento', 'skin/frontend', 'Mage.Cookies'],
        'Shopify' => ['shopify', 'cdn.shopify.com', 'shopify-payment-button'],
        'WooCommerce' => ['woocommerce', 'wc-api', 'wc_cart'],
        'PrestaShop' => ['prestashop', 'presta-', '/modules/ps_']
    ];
    
    // JavaScript Frameworks
    $jsPatterns = [
        'jQuery' => ['jquery', 'jQuery'],
        'React.js' => ['react', 'reactjs', '_reactRootContainer', '__REACT_DEVTOOLS_GLOBAL_HOOK__'],
        'Vue.js' => ['vue', '__vue__', 'vuex', 'nuxt'],
        'Angular' => ['ng-', 'angular', 'ng2', '_ng'],
        'Next.js' => ['__NEXT_DATA__', '_next/static'],
        'Svelte' => ['svelte-', '__SVELTE'],
        'Alpine.js' => ['alpine', 'x-data', 'x-bind'],
        'Backbone.js' => ['backbone', 'Backbone.View']
    ];
    
    // UI Frameworks
    $uiPatterns = [
        'Bootstrap' => ['bootstrap', 'navbar-toggle', 'container-fluid'],
        'Tailwind' => ['tailwind', 'tw-', 'space-y-'],
        'Material-UI' => ['MuiButton', 'MuiTypography', 'makeStyles'],
        'Bulma' => ['bulma', 'is-primary', 'is-info', 'navbar-burger'],
        'Foundation' => ['foundation.', 'orbit-container', 'top-bar'],
        'Semantic UI' => ['semantic', 'ui segment', 'ui grid']
    ];
    
    // Build Tools & Module Bundlers
    $buildTools = [
        'Webpack' => ['webpack', '__webpack_require__', 'webpackJsonp'],
        'Vite' => ['vite', '@vite', '/@vite'],
        'Parcel' => ['parcel', '_parcel'],
        'Rollup' => ['rollup', '_rollupJs']
    ];
    
    // CDNs & Asset Delivery
    $cdnPatterns = [
        'JSDelivr' => ['cdn.jsdelivr.net'],
        'Cloudflare' => ['cdnjs.cloudflare.com', 'cloudflare-static'],
        'Google CDN' => ['ajax.googleapis.com'],
        'Unpkg' => ['unpkg.com'],
        'CDNJS' => ['cdnjs.com']
    ];
    
    // Analytics & Marketing
    $analyticsPatterns = [
        'Google Analytics' => ['google-analytics', 'ga.js', 'analytics.js', 'gtag'],
        'Google Tag Manager' => ['googletagmanager', 'gtm.js'],
        'Facebook Pixel' => ['connect.facebook.net', 'fbq('],
        'HotJar' => ['hotjar', 'hjid:', 'hjsv:'],
        'Mixpanel' => ['mixpanel']
    ];
    
    // Server Technologies (from headers)
    if (!empty($headers)) {
        $server = $headers['Server'] ?? $headers['server'] ?? '';
        $poweredBy = $headers['X-Powered-By'] ?? $headers['x-powered-by'] ?? '';
        
        if (stripos($server, 'apache') !== false) $tech[] = "Apache";
        if (stripos($server, 'nginx') !== false) $tech[] = "Nginx";
        if (stripos($server, 'iis') !== false) $tech[] = "IIS";
        if (stripos($poweredBy, 'php') !== false) $tech[] = "PHP";
        if (stripos($poweredBy, 'asp.net') !== false) $tech[] = ".NET";
        if (stripos($poweredBy, 'express') !== false) $tech[] = "Express.js";
        
        // Cache & Performance
        if (isset($headers['X-Cache']) || isset($headers['X-Varnish'])) $tech[] = "Varnish Cache";
        if (isset($headers['CF-Cache-Status'])) $tech[] = "Cloudflare";
        if (isset($headers['X-Drupal-Cache'])) $tech[] = "Drupal";
    }
    
    // Check all patterns against HTML
    foreach ([$cmsPatterns, $jsPatterns, $uiPatterns, $buildTools, $cdnPatterns, $analyticsPatterns] as $category) {
        foreach ($category as $tech_name => $patterns) {
            foreach ($patterns as $pattern) {
                if (stripos($html, $pattern) !== false) {
                    $tech[] = $tech_name;
                    break;
                }
            }
        }
    }
    
    // Additional Specific Checks
    if (preg_match('/<link[^>]*fonts.(googleapis|gstatic).com[^>]*>/', $html)) {
        $tech[] = "Google Fonts";
    }
    if (preg_match('/<script[^>]*maps.google[^>]*>/', $html)) {
        $tech[] = "Google Maps";
    }
    if (preg_match('/<i[^>]*fa[- ]/', $html)) {
        $tech[] = "FontAwesome";
    }
    
    // Version Detection (where possible)
    if (preg_match('/bootstrap@([0-9.]+)/', $html, $matches)) {
        $index = array_search('Bootstrap', $tech);
        if ($index !== false) {
            $tech[$index] = "Bootstrap v" . $matches[1];
        }
    }
    
    // Remove duplicates and sort
    $tech = array_unique($tech);
    sort($tech);
    
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

function simulateShellUpload($url) {
    $testPaths = [
        // Common upload endpoints
        "/upload.php", "/upload", "/uploader", "/files/upload",
        "/admin/upload", "/api/upload", "/assets/upload",
        "/images/upload", "/media/upload", "/documents/upload",
        
        // Specific file upload endpoints
        "/upload.php?file=shell.php", "/upload?file=shell.jsp",
        "/api/upload?filename=cmd.php", "/upload/file?name=shell.phtml",
        
        // Bypass attempts
        "/upload?file=shell.php.jpg", "/upload?file=shell.php%00.jpg",
        "/upload?file=..%2F..%2Fshell.php", "/upload?file=shell.PhP",
        "/upload?file=shell.php;.jpg", "/upload?file=shell.php::$DATA",
        
        // Common CMS paths
        "/wp-content/uploads", "/administrator/components/upload",
        "/includes/upload", "/filemanager/upload"
    ];
    
    $shellSignatures = [
        '.php', '.phtml', '.php3', '.php4', '.php5', '.jsp', '.jspx',
        '.asp', '.aspx', '.cfm', '.cgi', 'cmd', 'shell', 'exec', 'system',
        'passthru', 'eval', 'base64'
    ];
    
    $successIndicators = [
        'upload', 'success', 'file', 'uploaded', 'complete',
        '200 OK', 'application/json', 'multipart/form-data'
    ];
    
    $results = [];
    
    // Limit testing to prevent timeouts
    $maxPaths = 5;
    $pathCount = 0;
    
    foreach ($testPaths as $path) {
        // Limit the number of tests
        if ($pathCount >= $maxPaths) {
            break;
        }
        $pathCount++;
        
        $checkUrl = rtrim($url, '/') . $path;
        
        // Test GET request
        $res = curlGet($checkUrl);
        if (is_array($res) && isset($res['error'])) {
            $res = "Error: " . $res['error'];
        }
        
        // Simulate POST request
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $checkUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, "file=test.php");
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: multipart/form-data',
            'X-Requested-With: XMLHttpRequest'
        ]);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        
        $postRes = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            $postRes = "Error: " . $error;
        }
        
        $suspicious = false;
        $reason = [];
        
        // Check for shell signatures
        foreach ($shellSignatures as $sig) {
            if (stripos($res . $postRes, $sig) !== false) {
                $suspicious = true;
                $reason[] = "Detected signature: $sig";
            }
        }
        
        // Check for success indicators
        foreach ($successIndicators as $indicator) {
            if (stripos($res . $postRes, $indicator) !== false) {
                $suspicious = true;
                $reason[] = "Found success indicator: $indicator";
            }
        }
        
        // Check response headers
        if (stripos($res, 'application/json') !== false || 
            stripos($res, 'multipart/form-data') !== false) {
            $suspicious = true;
            $reason[] = "Upload-compatible Content-Type detected";
        }
        
        $results[] = [
            "path" => $path,
            "result" => $suspicious ? "potentially exploitable" : "likely safe",
            "method_tested" => ["GET", "POST"],
            "reasons" => $reason,
            "response_length" => [
                "get" => strlen($res),
                "post" => strlen($postRes)
            ]
        ];
    }
    
    return $results;
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

[$headers, $html] = getHeadersAndHTML($url);

$dns = getDNS($host);
$ports = getOpenPorts($host);
$ssl = getSSLDetails($host);
$securityHeaders = getSecurityHeadersStatus($headers);
$cookies = getCookieData($headers);
$tech = detectTechStack($html, $headers);
$sql = simulateSQLi($url);
$xss = simulateXSS($url);
$shell = simulateShellUpload($url);

$external = [];
$external['ssl_labs'] = curlGet("https://api.ssllabs.com/api/v3/analyze?host=$host", true);
$external['security_headers'] = curlGet("https://securityheaders.com/?q=https://$host&followRedirects=on");
$external['ipinfo'] = curlGet("https://ipinfo.io/$ip/json", true);
$shodanKey = "h9YmSewS9IaS3mE9WufnBhNPH4v9Txav";
$external['shodan'] = curlGet("https://api.shodan.io/shodan/host/$ip?key=$shodanKey", true);

$end = endTimer($start);

header('Content-Type: application/json');
header('Content-Disposition: attachment; filename="output.json"');
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
