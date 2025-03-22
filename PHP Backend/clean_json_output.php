<?php

function simplifyDNS($records) {
    $a = [];
    $aaaa = [];
    $filtered = [];

    foreach ($records as $r) {
        if ($r['type'] === 'A') {
            if (!in_array($r['ip'], $a)) {
                $a[] = $r['ip'];
                $filtered[] = $r;
            }
        } elseif ($r['type'] === 'AAAA') {
            if (!in_array($r['ipv6'], $aaaa)) {
                $aaaa[] = $r['ipv6'];
                $filtered[] = $r;
            }
        } else {
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
        if (json_last_error() === JSON_ERROR_NONE) {
            $data[$key] = $decoded;
        } else {
            $data[$key] = "Could not parse JSON data";
        }
    }
}

// ==== LOAD RAW JSON FILE ====
$inputFile = "output (2).json";
$raw = file_get_contents($inputFile);

// Clean up any embedded HTML or PHP warning before JSON
$raw = preg_replace('/<br\\s*\\/?>.*?<br\\s*\\/?>/is', '', $raw);
$data = json_decode($raw, true);

if (!$data) {
    die("❌ Failed to parse JSON\n");
}

// ==== CLEAN PROCESS ====
$data["network"]["dns_records"] = simplifyDNS($data["network"]["dns_records"] ?? []);

truncateIfStringTooLong($data["external"], "ssl_labs", "Truncated SSL Labs data");
truncateIfStringTooLong($data["external"], "security_headers", "Truncated security headers HTML");

decodeJsonIfString($data["external"], "ipinfo");
decodeJsonIfString($data["external"], "shodan");

// ==== SAVE CLEAN JSON ====
$outputFile = "cleaned_output.json";
file_put_contents($outputFile, json_encode($data, JSON_PRETTY_PRINT));
echo "✅ Cleaned JSON saved to: $outputFile\n";
