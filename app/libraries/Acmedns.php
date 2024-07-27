<?php
class Acmedns {
    private $apiBaseUrl;

    public function __construct() {
    }

    public function setProvider($apiBaseUrl) {
        $this->apiBaseUrl = rtrim($apiBaseUrl, '/');
    }

    /**
     * Register a new domain with the ACME DNS service.
     *
     * @return array|false Returns an array with the registration details or false on failure.
     */
    public function registerDomain() {
        $url = $this->apiBaseUrl . '/register';

        $response = $this->makeRequest('POST', $url);

        return $response ? json_decode($response, true) : false;
    }

    /**
     * Update the TXT record for the given subdomain.
     *
     * @param string $username The API username.
     * @param string $password The API password.
     * @param string $subdomain The subdomain to update.
     * @param string $txtRecord The TXT record value to set (must be exactly 43 characters long).
     * @return bool Returns true on success, false on failure.
     */
    public function updateTxtRecord($username, $password, $subdomain, $txtRecord) {
        if (strlen($txtRecord) !== 43) {
            throw new InvalidArgumentException("The txt field must be exactly 43 characters long.");
        }

        $url = $this->apiBaseUrl . '/update';
        $data = [
            'subdomain' => $subdomain,
            'txt' => $txtRecord,
        ];

        $headers = [
            'X-Api-User: ' . $username,
            'X-Api-Key: ' . $password,
        ];

        $response = $this->makeRequest('POST', $url, json_encode($data), $headers);

        return $response !== false;
    }

    /**
     * Make an HTTP request.
     *
     * @param string $method The HTTP method (GET, POST, etc.).
     * @param string $url The URL to request.
     * @param string|null $data The data to send in the request body (for POST requests).
     * @param array $headers Additional headers to send with the request.
     * @return string|false Returns the response body or false on failure.
     */
    private function makeRequest($method, $url, $data = null, $headers = []) {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);

        if ($method === 'POST' && $data) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
            $headers[] = 'Content-Type: application/json';
        }

        if ($headers) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }

        $response = curl_exec($ch);

        if (curl_errno($ch)) {
            curl_close($ch);
            return false;
        }

        curl_close($ch);
        return $response;
    }
}