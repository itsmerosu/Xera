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

class ACME extends CI_Model
{
    protected $acme;
    private $keyPair;

	function __construct($autority)
	{
        /*
        $publicKeyPath = './acme-storage/'.'testemail@testing.com'.'/account.pub.pem';
        $privateKeyPath = './acme-storage/'.'testemail@testing.com'.'/account.pem';
        */
        $publicKeyPath = 'account.pub.pem';
        $privateKeyPath = 'account.pem';
        
        if (!file_exists($privateKeyPath)) {
            $keyPairGenerator = new KeyPairGenerator();
            $this->keyPair = $keyPairGenerator->generateKeyPair();
        
            file_put_contents($publicKeyPath, $this->keyPair->getPublicKey()->getPEM());
            file_put_contents($privateKeyPath, $this->keyPair->getPrivateKey()->getPEM());
        } else {
            $publicKey = new PublicKey(file_get_contents($publicKeyPath));
            $privateKey = new PrivateKey(file_get_contents($privateKeyPath));
            $this->keyPair = new KeyPair($publicKey, $privateKey);
        }
	}

    function initilize($autority)
    {
        $acme_directory = $this->fetch_base();
        if (array_key_exists($autority, $acme_directory)) {
            return 'Autority not valid.';
        }
        $acme_directory = $acme_directory[$autority];
        if ($acme_directory == 'not-set') {
            return 'Autority not set by the admin, please use another.';
        }
        $secureHttpClientFactory = new SecureHttpClientFactory(
            new GuzzleHttpClient(),
            new Base64SafeEncoder(),
            new KeyParser(),
            new DataSigner(),
            new ServerErrorHandler()
        );

        $secureHttpClient = $secureHttpClientFactory->createSecureHttpClient($this->keyPair);
        $this->acme = new AcmeClient($secureHttpClient, $acme_directory);
        return True;
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

        $challenges = $certificateOrder->getAuthorizationChallenges($domain);
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
        $challenge = $this->acme->challengeAuthorization($dnsChallenge);

        if ($challenge->getStatus() == 'valid') {
            $dn = new DistinguishedName($domain);
            $csr = new CertificateRequest($dn, $domainKeyPair);
            $this->acme->finalizeOrder($order, $csr, 180, false);
            return true;
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

        if ($order->getStatus() != 'issued') {
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
                        if ($order->getStatus() == 'processing') {
                            $status = 'processing';
                        } elseif ($order->getStatus() == 'valid') {
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

        $return = [
            'status' => $status,
            'begin_date' => $creationDate->format('Y-m-d'),
            'end_date' => $expirynDate->format('Y-m-d'),
            'csr_code' => $csrCode
        ];

        if ($status == 'processing') {
            $order = new CertificateOrder([], $orderId);
            $order = $this->acme->reloadOrder($order);
            $challenges = $order->getAuthorizationChallenges($domain);
            
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

            $challenge = $this->acme->challengeAuthorization($dnsChallenge);
            $digest = hash('sha256', $dnsChallenge->getPayload(), true);
            $base64urlDigest = rtrim(strtr(base64_encode($digest), '+/', '-_'), '=');
            $dnsContent = $base64urlDigest;
            $return['approver_method']['dns']['record'] = '_acme-challenge.'.$dnsChallenge->getDomain().' TXT '.$dnsContent;
        } else {
            $return['private_key'] = $privateKey->getPEM();
            $return['crt_code'] = $certificate['certificate_code'];
            $return['ca_code'] = $certificate['intermediate_code'];
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
                case 'processing':
                    $status = 'processing';
                    break;
                case 'valid':
                    $status = 'active';
                    break;
            
            }
            return $status;
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
        return $this->ssl->getOrderStatus($id);
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
			return $res['acme_zerossl'];
		}
		return false;
	}

    function get_googletrust()
	{
		$res = $this->fetch_base();
		if($res !== false)
		{
			return $res['acme_googletrust'];
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

    function set_zerossl($acme_directory)
	{
		$res = $this->update('zerossl', $acme_directory);
		if($res)
		{
			return true;
		}
		return false;
	}

    function set_googletrust($acme_directory)
	{
		$res = $this->update('googletrust', $acme_directory);
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