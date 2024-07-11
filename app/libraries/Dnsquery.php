<?php
use GuzzleHttp\Client;
class DNSQuery {
    function __construct()
    {
        
    }
    function queryDnsRecord($dnsServer, $domain, $recordType) {
        $recordTypes = [
            'CNAME' => 5,
            'TXT' => 16,
        ];
        if (!isset($recordTypes[$recordType])) {
            return "Unsupported record type";
        }
        $recordTypeValue = $recordTypes[$recordType];
        $id = rand(0, 65535);
        $header = pack('n', $id);
        $header .= pack('n', 0x0100);
        $header .= pack('n', 1);
        $header .= pack('n', 0);
        $header .= pack('n', 0);
        $header .= pack('n', 0);
        $question = '';
        foreach (explode('.', $domain) as $part) {
            $question .= chr(strlen($part)) . $part;
        }
        $question .= chr(0);
        $question .= pack('n', $recordTypeValue);
        $question .= pack('n', 1);
        $packet = $header . $question;
        $socket = fsockopen("udp://$dnsServer", 53, $errno, $errstr, 5);
        if (!$socket) {
            return "Socket creation failed: $errstr ($errno)";
        }
        if (!fwrite($socket, $packet, strlen($packet))) {
            return "Failed to send data";
        }
        $response = fread($socket, 512);
        if ($response === false) {
            return "Failed to receive data";
        }
        fclose($socket);
        $offset = 12;
        while (ord($response[$offset]) !== 0) {
            $offset += ord($response[$offset]) + 1;
        }
        $offset += 5;
        $numAnswers = unpack('n', substr($response, 6, 2))[1];
        if ($numAnswers == 0) {
            return false;
        }
        $offset += 10;
        $dataLength = unpack('n', substr($response, $offset, 2))[1];
        $offset += 2;
        $recordData = '';
        if ($recordType === 'CNAME') {
            $labels = [];
            while (ord($response[$offset]) !== 0) {
                $length = ord($response[$offset]);
                if ($length >= 192) {
                    $pointerOffset = unpack('n', substr($response, $offset, 2))[1] & 0x3FFF;
                    $offset += 2;
                    $labels[] = $this->parseDnsName($response, $pointerOffset);
                    return implode('.', $labels);
                } else {
                    $offset++;
                    $labels[] = substr($response, $offset, $length);
                    $offset += $length;
                }
            }
            $offset++;
            $recordData = implode('.', $labels);
        } elseif ($recordType === 'TXT') {
            $txtLength = ord($response[$offset]);
            $offset += 1;
            $recordData = substr($response, $offset, $txtLength);
        }
        return $recordData;
    }

    function parseDnsName($response, &$offset) {
        $labels = [];
        while (ord($response[$offset]) !== 0) {
            $length = ord($response[$offset]);
            if ($length >= 192) {
                $pointerOffset = unpack('n', substr($response, $offset, 2))[1] & 0x3FFF;
                $offset += 2;
                $labels[] = $this->parseDnsName($response, $pointerOffset);
                return implode('.', $labels);
            } else {
                $offset++;
                $labels[] = substr($response, $offset, $length);
                $offset += $length;
            }
        }
        $offset++;
        return implode('.', $labels);
    }

    function queryDnsRecordHttp($dnsServer, $domain, $recordType) {
        $client = new Client();
        $url = "https://$dnsServer/resolve?name=" . urlencode($domain) . "&type=$recordType";
        try {
            $response = $client->get($url);
            $body = $response->getBody()->getContents();

            $data = json_decode($body, true);
            if (!isset($data['Answer'])) {
                return false;
            }
            $records = $data['Answer'];
            if (empty($records)) {
                return false;
            }
            if ($recordType === 'CNAME') {
                return $records[0]['data'];
            } elseif ($recordType === 'TXT') {
                return $records[0]['data'];
            }
            return false;
        } catch (Exception $e) {
            return "Error: " . $e->getMessage();
        }
    }
}