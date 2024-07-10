<?php
class CloudFlareAPI{	
	private $api;
	private $zone_id;		
	public function __construct()
	{
    }	
	public function auth($mail,$api_key)
	{
		$api = [ 			
			"X-Auth-Email: $mail",
			"X-Auth-Key: $api_key",
			'Content-Type: application/json'
		];
        $this->api = $api;
    }	
	public function setZone($domain_name)
	{
		$this->zone_id = $this -> getZoneID($domain_name);
	}
	public function getZoneID($domain_name) {
		/* SENDING RESPONSE */
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, "https://api.cloudflare.com/client/v4/zones?name=$domain_name");
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_VERBOSE, 1);
		curl_setopt($ch, CURLOPT_HTTPHEADER, $this -> api);
		$content  = curl_exec($ch);
		curl_close($ch);
		/* PARSING RESPONSE */
		$response = json_decode($content,true);
		/* RETURN */
		//return $response['result'][0]['id'];
		return $response['result'][0]['id'];
	}
	public function listDNSrecords() {	
		/* SENDING RESPONSE */	
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, "https://api.cloudflare.com/client/v4/zones/".$this->zone_id."/dns_records/");
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_VERBOSE, 1);
		curl_setopt($ch, CURLOPT_HTTPHEADER, $this -> api);
		$content  = curl_exec($ch);
		curl_close($ch);
		/* PARSING RESPONSE */
		$response = json_decode($content,true);
		$return = [];		
		if($response['success'] == true){	
			/* RETURN */
			for($i = 0; $i < count($response); $i++) {
				$return[$i] = [
					"id" => $response['result'][$i]['id'],
					"type" => $response['result'][$i]['type'],
					"name" => $response['result'][$i]['name'],
					"proxied" => $response['result'][$i]['proxied'],
					"ttl" => $response['result'][$i]['ttl']
				];				
			}
			return $return;
		}	
		else{	
		return false;
		}
	}
	public function addDNSrecord($type,$name,$content,$ttl = 1,$cloudflare_proxy = false) {	
		/* PARSING RESPONSE */
		$ch = curl_init();		
		$payload = json_encode(  array( "type"=> $type,"name" => $name, "content" => $content, "ttl" => $ttl, "proxied" => $cloudflare_proxy ));
		curl_setopt( $ch, CURLOPT_POSTFIELDS, $payload );
		curl_setopt($ch, CURLOPT_URL, "https://api.cloudflare.com/client/v4/zones/".$this->zone_id."/dns_records/");
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_VERBOSE, 1);
		curl_setopt($ch, CURLOPT_HTTPHEADER, $this -> api);
		$content  = curl_exec($ch);
		curl_close($ch);
		/* PARSING RESPONSE */
		$response = json_decode($content,true);
		/* RETURN */
		if($response['success'] == true) {
			$list = [
				'status' => true,
				'id' => $response['result']['id'],
			];
			return $list;
		} else {
			$list = [
				'status' => false,
				'id' => 'none',
			];
			return $list;
		}
	}
	public function updateDNSrecord($dnsid,$type,$name,$content,$ttl = 1,$cloudflare_proxy = false)
	{	
		/* PARSING RESPONSE */
		$data = null;
		$ch = curl_init(); 	
		$payload = json_encode( array( "type"=> $type,"name" => $name, "content" => $content,"data" => $data, "ttl" => $ttl, "proxied" => $cloudflare_proxy ) );
		curl_setopt( $ch, CURLOPT_POSTFIELDS, $payload );
		curl_setopt($ch, CURLOPT_URL, "https://api.cloudflare.com/client/v4/zones/".$this->zone_id."/dns_records/".$dnsid);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PATCH");
		curl_setopt($ch, CURLOPT_VERBOSE, 1);
		curl_setopt($ch, CURLOPT_HTTPHEADER, $this -> api);
		$content  = curl_exec($ch);
		curl_close($ch);
		/* PARSING RESPONSE */
		$response = json_decode($content,true);
		/* RETURN */
		if($response['success'] == true)
		return true;
		else
		return false;
	}
	public function deleteDNSrecord($dnsid){	
		/* PARSING RESPONSE */	
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, "https://api.cloudflare.com/client/v4/zones/".$this->zone_id."/dns_records/".$dnsid);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
		curl_setopt($ch, CURLOPT_VERBOSE, 1);
		curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
		curl_setopt($ch, CURLOPT_HTTPHEADER, $this -> api);
		$content  = curl_exec($ch);
		curl_close($ch);
		/* PARSING RESPONSE */
		$response = json_decode($content,true);
		
		/* RETURN */
		if($response['success'] == true)
		return true;
		else
		return false;
	}
}
?>