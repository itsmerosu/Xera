<?php 
use AcmePhp\Ssl\Certificate;
use AcmePhp\Ssl\Generator\KeyPairGenerator;
use InfinityFree\AcmeCore\Http\Base64SafeEncoder;
use InfinityFree\AcmeCore\Http\SecureHttpClientFactory;
use InfinityFree\AcmeCore\Http\ServerErrorHandler;
use AcmePhp\Ssl\KeyPair;
use AcmePhp\Ssl\PrivateKey;
use AcmePhp\Ssl\PublicKey;
use AcmePhp\Ssl\Parser\KeyParser;
use AcmePhp\Ssl\Signer\DataSigner;
use GuzzleHttp\Client as GuzzleHttpClient;
use InfinityFree\AcmeCore\AcmeClient;
use AcmePhp\Ssl\DistinguishedName;
use AcmePhp\Ssl\CertificateRequest;
use AcmePhp\Ssl\Signer\CertificateRequestSigner;
use InfinityFree\AcmeCore\Protocol\ExternalAccount;
use InfinityFree\AcmeCore\Protocol\CertificateOrder;
use PurplePixie\PhpDns\DNSQuery;

class acme extends CI_Model
{
    protected $acme;
    private $keyPair;
    private $publicKeyPath;
    private $privateKeyPath;

	function __construct()
	{
        $this->publicKeyPath = './acme-storage/'.$this->user->get_email().'/eab/account.pub.pem';
        $this->privateKeyPath = './acme-storage/'.$this->user->get_email().'/eab/account.pem';
        $directory = './acme-storage/'.$this->user->get_email().'/eab/';
        if (!file_exists($directory )) {
            mkdir($directory , 0777, true);
        }
        /*
        $publicKeyPath = 'account.pub.pem';
        $privateKeyPath = 'account.pem';
        */
        
        if (file_exists($this->privateKeyPath)) {
            $publicKey = new PublicKey(file_get_contents($this->publicKeyPath));
            $privateKey = new PrivateKey(file_get_contents($this->privateKeyPath));
            $this->keyPair = new KeyPair($publicKey, $privateKey);
        }
	}

    function initilize($autority)
    {
        $ca_settings = $this->fetch_base();
        if (!array_key_exists('acme_'.$autority, $ca_settings)) {
            return 'Autority not valid.';
        }
        $ca_settings = $ca_settings['acme_'.$autority];
        if ($ca_settings == 'not-set') {
            return 'Autority not set by the admin, please use another.';
        }
        
        if (!file_exists($this->privateKeyPath)) {
            $keyPairGenerator = new KeyPairGenerator();
            $this->keyPair = $keyPairGenerator->generateKeyPair();
            file_put_contents($this->publicKeyPath, $this->keyPair->getPublicKey()->getPEM());
            file_put_contents($this->privateKeyPath, $this->keyPair->getPrivateKey()->getPEM());
            
            $secureHttpClientFactory = new SecureHttpClientFactory(
                new GuzzleHttpClient(),
                new Base64SafeEncoder(),
                new KeyParser(),
                new DataSigner(),
                new ServerErrorHandler()
            );

            $secureHttpClient = $secureHttpClientFactory->createSecureHttpClient($this->keyPair);
            if ($autority == 'letsencrypt') {
                $this->acme = new AcmeClient($secureHttpClient, $ca_settings);
                $this->acme->registerAccount($this->user->get_email());
                return True;
            } elseif ($autority == 'zerossl') {
                $ca_settings = $this->get_zerossl();
                if ($ca_settings['url'] != '' && $ca_settings['eab_kid'] != '' && $ca_settings['eab_hmac_key'] != '') {
                    $this->acme = new AcmeClient($secureHttpClient, $ca_settings['url']);
                    $this->acme->registerAccount($this->user->get_email(), new ExternalAccount($ca_settings['eab_kid'], $ca_settings['eab_hmac_key']));
                    return True;
                }
            } elseif ($autority == 'googletrust') {
                $ca_settings = $this->get_googletrust();
                if ($ca_settings['url'] != '' && $ca_settings['eab_kid'] != '' && $ca_settings['eab_hmac_key'] != '') {
                    $this->acme = new AcmeClient($secureHttpClient, $ca_settings['url']);
                    $this->acme->registerAccount($this->user->get_email(), new ExternalAccount($ca_settings['eab_kid'], $ca_settings['eab_hmac_key']));
                    return True;
                }
            }
            return False;
        } else {
            $secureHttpClientFactory = new SecureHttpClientFactory(
                new GuzzleHttpClient(),
                new Base64SafeEncoder(),
                new KeyParser(),
                new DataSigner(),
                new ServerErrorHandler()
            );

            $secureHttpClient = $secureHttpClientFactory->createSecureHttpClient($this->keyPair);
            if ($autority == 'letsencrypt') {
                $this->acme = new AcmeClient($secureHttpClient, $ca_settings);
                $this->acme->registerAccount($this->user->get_email());
                return True;
            } elseif ($autority == 'zerossl') {
                $ca_settings = $this->get_zerossl();
                if ($ca_settings['url'] != '' && $ca_settings['eab_kid'] != '' && $ca_settings['eab_hmac_key'] != '') {
                    $this->acme = new AcmeClient($secureHttpClient, $ca_settings['url']);
                    $this->acme->registerAccount($this->user->get_email(), new ExternalAccount($ca_settings['eab_kid'], $ca_settings['eab_hmac_key']));
                    return True;
                }
            } elseif ($autority == 'googletrust') {
                $ca_settings = $this->get_googletrust();
                if ($ca_settings['url'] != '' && $ca_settings['eab_kid'] != '' && $ca_settings['eab_hmac_key'] != '') {
                    $this->acme = new AcmeClient($secureHttpClient, $ca_settings['url']);
                    $this->acme->registerAccount($this->user->get_email(), new ExternalAccount($ca_settings['eab_kid'], $ca_settings['eab_hmac_key']));
                    return True;
                }
            }
            return False;
        }
    }
    
    function registerAccount()
    {
        $this->acme->registerAccount(null, new ExternalAccount($this->user->get_id(), 'mailto:'.$this->user->get_email()));
    }

    public function create_ssl($domain, $autority)
    {
        $keyPairGenerator = new KeyPairGenerator();
        $domainKeyPair = $keyPairGenerator->generateKeyPair();

        $certificateOrder = $this->acme->requestOrder([$domain]);

        $allChallenges = $certificateOrder->getAuthorizationChallenges();

        $challenges = $allChallenges[$domain];
        $dnsChallenge = null;
        foreach ($challenges as $challenge) {
            if ($challenge->getType() === 'dns-01') {
                $dnsChallenge = $challenge;
                break;
            }
        }
        if (!$dnsChallenge) {
            throw new Exception('DNS-01 challenge not found.');
        }

        $dn = new DistinguishedName($domain);
        $csr = new CertificateRequest($dn, $domainKeyPair);
        $csrSigner = new CertificateRequestSigner();
        $csrCode = $csrSigner->signCertificateRequest($csr);

        $key = md5($this->base->get_hostname() . ':' . $this->user->get_email() . ':' . $certificateOrder->getOrderEndpoint() . ':' . time());
        $data = [
            'ssl_pid' => $certificateOrder->getOrderEndpoint(),
            'ssl_key' => $key,
            'ssl_for' => $this->user->get_key(),
            'ssl_private' => $domainKeyPair->getPrivateKey()->getPEM(),
            'ssl_type' => $autority
        ];
        $res = $this->db->insert('is_ssl', $data);
		if($res !== false)
		{
			return true;
		}
		return false;
    }

    public function checkValidation($orderId, $privateKey)
    {
        $privateKey = new PrivateKey($privateKey);
        $publicKey = $privateKey->getPublicKey();
        $domainKeyPair = new KeyPair($publicKey, $privateKey);
        
        $order = new CertificateOrder([], $orderId);
        $order = $this->acme->reloadOrder($order);
        $allChallenges = $order->getAuthorizationChallenges();
        $domain = array_key_first($allChallenges);

        $challenges = $allChallenges[$domain];
        
        $dnsChallenge = null;
        foreach ($challenges as $challenge) {
            if ($challenge->getType() === 'dns-01') {
                $dnsChallenge = $challenge;
                break;
            }
        }
        if (!$dnsChallenge) {
            return false;
        }

        $query = new DNSQuery("8.8.8.8");
        $digest = hash('sha256', $dnsChallenge->getPayload(), true);
        $base64urlDigest = rtrim(strtr(base64_encode($digest), '+/', '-_'), '=');
        $name = '_acme-challenge.'.$dnsChallenge->getDomain();
        $dnsContent = $base64urlDigest;
        $result = $query->query($name, \PurplePixie\PhpDns\DNSTypes::NAME_TXT);

        if ($result->current()->getData() == $dnsContent) {
            $challenge = $this->acme->challengeAuthorization($dnsChallenge);
            if ($challenge->getStatus() == 'valid') {
                $dn = new DistinguishedName($domain);
                $csr = new CertificateRequest($dn, $domainKeyPair);
                $this->acme->finalizeOrder($order, $csr, 180, false);
                return true;
            }
        }
        return false;
    }

    public function getCertificate($orderId, $privateKey)
    {
        $privateKey = new PrivateKey($privateKey);
        $publicKey = $privateKey->getPublicKey();
        $domainKeyPair = new KeyPair($publicKey, $privateKey);

        $order = new CertificateOrder([], $orderId);
        $order = $this->acme->reloadOrder($order);

        if ($order->getStatus() == 'valid') {
            $certificate = $this->acme->retrieveCertificate($order);

            $privateKey = $domainKeyPair->getPrivateKey()->getPem();
            $certificateCode = $certificate->getPem();
            $intermediateCode = $certificate->getIssuerCertificate()->getPEM();

            $return = [
                'private_key' => $privateKey,
                'certificate_code' => $certificateCode,
                'intermediate_code' => $intermediateCode,
            ];

            return $return;
        }
        return False;
    }

    function get_ssl_info($key)
    {
        $res = $this->fetch(['key' => $key]);
		if($res !== []) {
            $orderId = $res[0]['ssl_pid'];
            $privateKey = $res[0]['ssl_private'];
        } else {
            return False;
        }
        $privateKey = new PrivateKey($privateKey);
        $publicKey = $privateKey->getPublicKey();
        $domainKeyPair = new KeyPair($publicKey, $privateKey);

        $order = new CertificateOrder([], $orderId);
        $order = $this->acme->reloadOrder($order);

        $allChallenges = $order->getAuthorizationChallenges();
        $domain = array_key_first($allChallenges);

        $dn = new DistinguishedName($domain);
        $csr = new CertificateRequest($dn, $domainKeyPair);
        $csrSigner = new CertificateRequestSigner();
        $csrCode = $csrSigner->signCertificateRequest($csr);

        if ($order->getStatus()) {
            switch ($order->getStatus()) {
                case 'invalid':
                    $status = 'cancelled';
                    break;
                case 'pending':
                    $status = 'processing';
                    if ($this->checkValidation($orderId, $privateKey->getPEM())) {
                        if ($order->getStatus() == 'valid') {
                            $status = 'active';
                        }
                    }
                    break;
                case 'ready':
                    $status = 'processing';
                    if ($this->checkValidation($orderId, $privateKey->getPEM())) {
                        if ($order->getStatus() == 'valid') {
                            $status = 'active';
                        }
                    }
                    break;
                case 'processing':
                    $status = 'processing';
                    break;
                case 'valid':
                    $status = 'active';
                    break;
            
            }
        }
        $type = 'Unknow';
        switch ($this->ssl->get_ssl_type($key)) {
            case 'letsencrypt':
                $type = "Let's Encrypt";
            case 'zerossl':
                $type = "ZeroSSL";
            case 'googletrust':
                $type = "Google Trust Services";
            case 'gogetssl':
                $type = "GoGetSSL";
        }
        
        $return = [
            'status' => $status,
            'begin_date' => '---- -- --',
            'end_date' => '---- -- --',
            'csr_code' => $csrCode,
            'domain' => $domain,
            'type' => $type
        ];
        if ($status == 'processing') {
            $order = new CertificateOrder([], $orderId);
            $order = $this->acme->reloadOrder($order);
            
            $allChallenges = $order->getAuthorizationChallenges();
            $domain = array_key_first($allChallenges);
            $challenges = $allChallenges[$domain];
            
            $dnsChallenge = null;
            foreach ($challenges as $challenge) {
                if ($challenge->getType() === 'dns-01') {
                    $dnsChallenge = $challenge;
                    break;
                }
            }
            if (!$dnsChallenge) {
                return False;
            }

            $digest = hash('sha256', $dnsChallenge->getPayload(), true);
            $base64urlDigest = rtrim(strtr(base64_encode($digest), '+/', '-_'), '=');
            $dnsContent = $base64urlDigest;
            $return['approver_method']['dns']['record'] = '_acme-challenge.'.$dnsChallenge->getDomain().' TXT '.$dnsContent;
        } elseif ($this->getCertificate($orderId, $privateKey->getPEM())) {
            $return['private_key'] = $privateKey->getPEM();

            $certificate = $this->getCertificate($orderId, $privateKey->getPEM());
            if ($certificate == False) {
                return False;
            }
            $cert = openssl_x509_read($certificate['certificate_code']);

            $creationDate = openssl_x509_parse($cert)['validFrom_time_t'];
            $expirynDate = openssl_x509_parse($cert)['validTo_time_t'];
            $creationDate = new DateTime("@$creationDate");
            $expirynDate = new DateTime("@$expirynDate");

            if (new DateTime() >= $expirynDate) {
                $status = 'expired';
            }

            $return['begin_date'] = $creationDate->format('Y-m-d');
            $return['end_date'] = $expirynDate->format('Y-m-d');
            $return['crt_code'] = $certificate['certificate_code'];
            $return['ca_code'] = $certificate['intermediate_code'];
        } else {
            $return['private_key'] = $privateKey->getPEM();
            $return['begin_date'] = '---- -- --';
            $return['end_date'] = '---- -- --';
            $return['crt_code'] = '';
            $return['ca_code'] = '';
        }
        return $return;
    }

    function getOrderStatus($orderId) {
        $order = new CertificateOrder([], $orderId);
        $order = $this->acme->reloadOrder($order);
        if ($order->getStatus()) {
            switch ($order->getStatus()) {
                case 'invalid':
                    $status = 'cancelled';
                    break;
                case 'pending':
                    $status = 'processing';
                    break;
                case 'ready':
                    $status = 'processing';
                    break;
                case 'processing':
                    $status = 'processing';
                    break;
                case 'valid':
                    $status = 'active';
                    break;
            
            }
            $allChallenges = $order->getAuthorizationChallenges();
            $domain = array_key_first($allChallenges);
            return [
                'status' => $status,
                'domain' => $domain
            ];
        }
        return False;
    }

    function cancel_ssl($key, $reason)
    {
        $res = $this->fetch(['key' => $key]);
		if($res !== []) {
            $orderId = $res[0]['ssl_pid'];
            $privateKey = $res[0]['ssl_private'];
        } else {
            return False;
        }

        $certificate = $this->getCertificate($orderId, $privateKey);

        if ($this->acme->revokeCertificate(new Certificate($certificate['certificate_code'], $reason))) {
            return True;
        }
        return False;
    }

    function getOrderStatus_goget($id)
    {
        $this->load->model(['gogetssl' => 'ssl']);
        return $this->ssl->getStatus($id);
    }

    function get_ssl_list()
	{
		$res = $this->fetch(['for' => $this->user->get_key()]);
		if($res !== false)
		{
			$arr = [];
			if(count($res)>0)
			{
				foreach ($res as $key) {
                    if ($key['ssl_type'] == 'gogetssl') {
                        $data = $this->getOrderStatus_goget($key['ssl_pid']);
                    } elseif ($key['ssl_type'] == 'letsencrypt') {
                        $this->initilize($key['ssl_type']);
                        $data = $this->getOrderStatus($key['ssl_pid']);
                    } elseif ($key['ssl_type'] == 'zerossl') {
                        $this->initilize($key['ssl_type']);
                        $data = $this->getOrderStatus($key['ssl_pid']);
                    } elseif ($key['ssl_type'] == 'googletrust') {
                        $this->initilize($key['ssl_type']);
                        $data = $this->getOrderStatus($key['ssl_pid']);
                    }
					$data['key'] = $key['ssl_key'];
					$arr[] = $data;
				}
				return $arr;
			}
			return $arr;
		}
		return false;
	}

	function get_ssl_list_all($count = 0)
	{
		$res = $this->fetch();
		if($res !== false)
		{
			$arr = [];
			if(count($res)>0)
			{
				foreach ($res as $key) {
					if ($key['ssl_type'] == 'gogetssl') {
                        $data = $this->getOrderStatus_goget($key['ssl_pid']);
                    } elseif ($key['ssl_type'] == 'letsencrypt') {
                        $this->initilize($key['ssl_type']);
                        $data = $this->getOrderStatus($key['ssl_pid']);
                    } elseif ($key['ssl_type'] == 'zerossl') {
                        $this->initilize($key['ssl_type']);
                        $data = $this->getOrderStatus($key['ssl_pid']);
                    } elseif ($key['ssl_type'] == 'googletrust') {
                        $this->initilize($key['ssl_type']);
                        $data = $this->getOrderStatus($key['ssl_pid']);
                    }
					$data['key'] = $key['ssl_key'];
					$arr[] = $data;
				}
				return $arr;
			}
			$list = [];
			if($count != 0)
			{
				$count = $count * $this->base->rpp();
			}
			for ($i = $count; $i < count($arr); $i++) { 
				if($i >= $count + $this->base->rpp())
				{
					break;
				}
				else
				{
					$list[] = $arr[$i];
				}
			}
			return $list;
		}
		return false;
	}

	function list_count()
	{
		$res = $this->fetch();
		if($res !== false)
		{
			$arr = [];
			if(count($res)>0)
			{
				foreach ($res as $key) {
					if ($key['ssl_type'] == 'gogetssl') {
                        $data = $this->getOrderStatus_goget($key['ssl_pid']);
                    } elseif ($key['ssl_type'] == 'letsencrypt') {
                        $this->initilize($key['ssl_type']);
                        $data = $this->getOrderStatus($key['ssl_pid']);
                    } elseif ($key['ssl_type'] == 'zerossl') {
                        $this->initilize($key['ssl_type']);
                        $data = $this->getOrderStatus($key['ssl_pid']);
                    } elseif ($key['ssl_type'] == 'googletrust') {
                        $this->initilize($key['ssl_type']);
                        $data = $this->getOrderStatus($key['ssl_pid']);
                    }
					$data['key'] = $key['ssl_key'];
					$arr[] = $data;
				}
			}
			return count($arr);
		}
		return false;
	}

    function get_letsencrypt()
	{
		$res = $this->fetch_base();
		if($res !== false)
		{
			return $res['acme_letsencrypt'];
		}
		return false;
	}

    function get_zerossl()
	{
		$res = $this->fetch_base();
		if($res !== false)
		{
            if ($res['acme_zerossl'] != 'not-set') {
                $zerossl = json_decode($res['acme_zerossl'], true);
                $return = [
                    'url' => $zerossl['url'],
                    'eab_kid' => $zerossl['eab_kid'],
                    'eab_hmac_key' => $zerossl['eab_hmac_key']
                ];
			    return $return;
            } else {
                return 'not-set';
            }
		}
		return false;
	}

    function get_googletrust()
	{
		$res = $this->fetch_base();
		if($res !== false)
		{
            if ($res['acme_googletrust'] != 'not-set') {
                $googletrust = json_decode($res['acme_googletrust'], true);
                $return = [
                    'url' => $googletrust['url'],
                    'eab_kid' => $googletrust['eab_kid'],
                    'eab_hmac_key' => $googletrust['eab_hmac_key']
                ];
			    return $return;
            } else {
                return 'not-set';
            }
		}
		return false;
	}

    function set_letsencrypt($acme_directory)
	{
		$res = $this->update('letsencrypt', $acme_directory);
		if($res)
		{
			return true;
		}
		return false;
	}

    function set_zerossl($zerossl)
	{
        if ($zerossl == 'not-set') {
            $res = $this->update('zerossl', $zerossl);
        } else {
            if ($zerossl['url'] == '' && $zerossl['eab_kid'] == '' && $zerossl['eab_hmac_key'] == '') {
                $zerossl = 'not-set';
            } else {
                $zerossl = json_encode($zerossl);
            }
            $res = $this->update('zerossl', $zerossl);
        }
		if($res)
		{
			return true;
		}
		return false;
	}

    function set_googletrust($googletrust)
	{
        if ($googletrust == 'not-set') {
            $res = $this->update('googletrust', $googletrust);
        } else {
            if ($googletrust['url'] == '' && $googletrust['eab_kid'] == '' && $googletrust['eab_hmac_key'] == '') {
                $googletrust = 'not-set';
            } else {
                $googletrust = json_encode($googletrust);
            }
        }
		if($res)
		{
			return true;
		}
		return false;
	}
	
	function is_active()
	{
		$res = $this->fetch_base();
		if($res !== false)
		{
			if($res['acme_status'] === 'active')
			{
				return true;
			}
			return false;
		}
		return false;
	}

	function get_status()
	{
		$res = $this->fetch_base();
		if($res !== false)
		{
			return $res['acme_status'];
		}
		return false;
	}

    function set_status(bool $status)
	{
		if($status === true)
		{ 
			$status = 'active';
		}
		else
		{
			$status = 'inactive';
		}
		$res = $this->update('status', $status);
		if($res)
		{
			return true;
		}
		return false;
	}

    private function update($index, $value)
	{
		$res = $this->base->update(
			[$index => $value],
			['id' => 'xera_acme'],
			'is_acme',
			'acme_'
		);
		if($res)
		{
			return true;
		}
		return false;
	}

    private function fetch_base()
	{
		$res = $this->base->fetch(
			'is_acme',
			['id' => 'xera_acme'],
			'acme_'
		);
		if(count($res) > 0)
		{
			return $res[0];
		}
		return false;
	}

	private function fetch($where = [])
	{
		$res = $this->base->fetch(
			'is_ssl',
			$where,
			'ssl_'
		);
		return $res;
	}
}
