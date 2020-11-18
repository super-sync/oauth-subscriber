<?php

namespace GuzzleHttp\Subscriber\Oauth;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use GuzzleHttp\MessageFormatter;
use GuzzleHttp\Promise;
use Psr\Http\Message\StreamInterface;

/**
 * OAuth 1.0 signature plugin.
 *
 * Portions of this code comes from HWIOAuthBundle and a Guzzle 3 pull request:
 * @author Alexander <iam.asm89@gmail.com>
 * @author Joseph Bielawski <stloyd@gmail.com>
 * @author Francisco Facioni <fran6co@gmail.com>
 * @link https://github.com/hwi/HWIOAuthBundle
 * @link https://github.com/guzzle/guzzle/pull/563 Original Guzzle 3 pull req.
 *
 * @link http://oauth.net/core/1.0/#rfc.section.9.1.1 OAuth specification
 */
class Oauth
{
    /**
     * Consumer request method constants. See http://oauth.net/core/1.0/#consumer_req_param
     */
    const REQUEST_METHOD_HEADER = 'header';
    const REQUEST_METHOD_QUERY  = 'query';

    /**
     * Default signature methods for the three algorithm types
     */
    const SIGNATURE_METHOD_HMAC      = 'HMAC-SHA256';
    const SIGNATURE_METHOD_RSA       = 'RSA-SHA1';
    const SIGNATURE_METHOD_PLAINTEXT = 'PLAINTEXT';

    /** @var array Configuration settings */
    private $config;

    /**
     * Create a new OAuth 1.0 plugin.
     *
     * The configuration array accepts the following options:
     *
     * - request_method: Consumer request method. One of 'header' or 'query'.
     *   Defaults to 'header'.
     * - callback: OAuth callback
     * - consumer_key: Consumer key string. Defaults to "anonymous".
     * - consumer_secret: Consumer secret. Defaults to "anonymous".
     * - private_key_file: The location of your private key file (RSA-SHA1 signature method only)
     * - private_key_passphrase: The passphrase for your private key file (RSA-SHA1 signature method only)
     * - token: Client token
     * - token_secret: Client secret token
     * - verifier: OAuth verifier.
     * - version: OAuth version. Defaults to '1.0'.
     * - realm: OAuth realm.
     * - signature_method: Signature method. One of 'HMAC-SHA1', 'RSA-SHA1', or
     *   'PLAINTEXT'. Defaults to 'HMAC-SHA1'.
     *
     * @param array $config Configuration array.
     */
    public function __construct($config)
    {
        // Defaults
        $this->config = [
            'version'          => '1.0',
            'request_method'   => self::REQUEST_METHOD_HEADER,
            'consumer_key'     => 'anonymous',
            'consumer_secret'  => 'anonymous',
            'signature_method' => self::SIGNATURE_METHOD_HMAC,
        ];

        foreach ($config as $key => $value) {
            $this->config[$key] = $value;
        }

        /**
         * This is so that existing code is not deprecated by requirement for a new config to be passed to this constructor.
         * Only the signature_method param needs to change here
         */
        $this->config['hashing_algorithm'] = $this->getHashingAlgorithm();

        return;
    }

    /**
     * Gets the hashing algorithm from the selected Signature Method
     * 
     * @return string
     */
    private function getHashingAlgorithm()
    {
        if ($this->config['signature_method'] == 'PLAINTEXT')
            return $this->config['signature_method'];

        $algo = str_replace('hmac-', '', str_replace('rsa-', '', strtolower($this->config['signature_method'])));
        $this->checkAlgo($algo);

        return $algo;
    }

    /**
     * Checks whether the algorithm is supportable
     * 
     * @param string $algo
     * 
     * @return void
     * @throws \RuntimeException
     */
    private function checkAlgo($algo)
    {
        if (!in_array($algo, hash_hmac_algos()))
            throw new \RuntimeException("Algorithm \"" . $algo . "\" not supported");
        
        return;
    }

    /**
     * Called when the middleware is handled.
     *
     * @param callable $handler
     *
     * @return \Closure
     */
    public function __invoke(callable $handler)
    {
        return function ($request, array $options) use ($handler) {

            if (isset($options['auth']) && $options['auth'] == 'oauth') {
                $request = $this->onBefore($request);
            }

            return $handler($request, $options);
        };
    }

    private function onBefore(RequestInterface $request)
    {
        $oauthparams = $this->getOauthParams(
            $this->generateNonce($request),
            $this->config
        );

        $oauthparams['oauth_signature'] = $this->getSignature($request, $oauthparams);
        uksort($oauthparams, 'strcmp');

        switch ($this->config['request_method']) {
            case self::REQUEST_METHOD_HEADER:
                list($header, $value) = $this->buildAuthorizationHeader($oauthparams);
                $request = $request->withHeader($header, $value);
                break;
            case self::REQUEST_METHOD_QUERY:
                $queryparams = \GuzzleHttp\Psr7\parse_query($request->getUri()->getQuery());
                $preparedParams = \GuzzleHttp\Psr7\build_query($oauthparams + $queryparams);
                $request = $request->withUri($request->getUri()->withQuery($preparedParams));
                break;
            default:
                throw new \InvalidArgumentException(sprintf(
                    'Invalid consumer method "%s"',
                    $this->config['request_method']
                ));
        }

        return $request;
    }

    /**
     * Calculate signature for request
     *
     * @param RequestInterface $request Request to generate a signature for
     * @param array            $params  Oauth parameters.
     *
     * @return string
     *
     * @throws \RuntimeException
     */
    public function getSignature(RequestInterface $request, array $params)
    {
        // Remove oauth_signature if present
        // Ref: Spec: 9.1.1 ("The oauth_signature parameter MUST be excluded.")
        unset($params['oauth_signature']);

        // Add POST fields if the request uses POST fields and no files
        if ($request->getHeaderLine('Content-Type') == 'application/x-www-form-urlencoded') {
            $body = \GuzzleHttp\Psr7\parse_query($request->getBody()->getContents());
            $params += $body;
        }

        // Parse & add query string parameters as base string parameters
        $query = $request->getUri()->getQuery();
        $params += \GuzzleHttp\Psr7\parse_query($query);

        $baseString = $this->createBaseString(
            $request,
            $this->prepareParameters($params)
        );

        // Implements double-dispatch to sign requests
        if (strpos(strtolower($this->config['signature_method']), 'sha') !== false) {
            $signature = $this->signUsingHmacSha($baseString);
        } elseif (strpos(strtolower($this->config['signature_method']), 'rsa') !== false) {
            $signature = $this->signUsingRsaSha($baseString);
        } elseif ($this->confi['signature_method'] == self::SIGNATURE_METHOD_PLAINTEXT) {
            $signature = $this->signUsingPlaintext($baseString);
        } else {
            throw new \RuntimeException('Unknown signature method: ' . $this->config['signature_method']);
        }

        return base64_encode($signature);
    }

    /**
     * Returns a Nonce Based on the unique id and URL.
     *
     * This will allow for multiple requests in parallel with the same exact
     * timestamp to use separate nonce's.
     *
     * @param RequestInterface $request Request to generate a nonce for
     *
     * @return string
     */
    public function generateNonce(RequestInterface $request)
    {
        return sha1(uniqid('', true) . $request->getUri()->getHost() . $request->getUri()->getPath());
    }

    /**
     * Creates the Signature Base String.
     *
     * The Signature Base String is a consistent reproducible concatenation of
     * the request elements into a single string. The string is used as an
     * input in hashing or signing algorithms.
     *
     * @param RequestInterface $request Request being signed
     * @param array            $params  Associative array of OAuth parameters
     *
     * @return string Returns the base string
     * @link http://oauth.net/core/1.0/#sig_base_example
     */
    protected function createBaseString(RequestInterface $request, array $params)
    {
        // Remove query params from URL. Ref: Spec: 9.1.2.
        $url = $request->getUri()->withQuery('');
        $query = http_build_query($params, '', '&', PHP_QUERY_RFC3986);

        return strtoupper($request->getMethod())
            . '&' . rawurlencode($url)
            . '&' . rawurlencode($query);
    }

    /**
     * Convert booleans to strings, removed unset parameters, and sorts the array
     *
     * @param array $data Data array
     *
     * @return array
     */
    private function prepareParameters($data)
    {
        // Parameters are sorted by name, using lexicographical byte value
        // ordering. Ref: Spec: 9.1.1 (1).
        uksort($data, 'strcmp');

        foreach ($data as $key => $value) {
            if ($value === null) {
                unset($data[$key]);
            }
        }

        return $data;
    }

    /**
     * @param string $baseString
     *
     * @return string
     */
    private function signUsingHmacSha($baseString)
    {
        $key = rawurlencode($this->config['consumer_secret'])
            . '&' . rawurlencode($this->config['token_secret']);

        return hash_hmac(strtolower($this->config['hashing_algorithm']), $baseString, $key, true);
    }

    /**
     * @param string $baseString
     *
     * @return string
     */
    private function signUsingRsaSha($baseString)
    {
        if (!function_exists('openssl_pkey_get_private')) {
            throw new \RuntimeException('RSA-SHA1 signature method '
                . 'requires the OpenSSL extension.');
        }

        $privateKey = openssl_pkey_get_private(
            file_get_contents($this->config['private_key_file']),
            $this->config['private_key_passphrase']
        );

        $signature = '';
        openssl_sign($baseString, $signature, $privateKey);
        openssl_free_key($privateKey);

        return $signature;
    }

    /**
     * @param string $baseString
     *
     * @return string
     */
    private function signUsingPlaintext($baseString)
    {
        return $baseString;
    }

    /**
     * Builds the Authorization header for a request
     *
     * @param array $params Associative array of authorization parameters.
     *
     * @return array
     */
    private function buildAuthorizationHeader(array $params)
    {
        foreach ($params as $key => $value) {
            $params[$key] = $key . '="' . rawurlencode($value) . '"';
        }

        if (isset($this->config['realm'])) {
            array_unshift(
                $params,
                'realm="' . rawurlencode($this->config['realm']) . '"'
            );
        }

        return ['Authorization', 'OAuth ' . implode(', ', $params)];
    }

    /**
     * Get the oauth parameters as named by the oauth spec
     *
     * @param string     $nonce  Unique nonce
     * @param array      $config Configuration options of the plugin.
     *
     * @return array
     */
    private function getOauthParams($nonce, array $config)
    {
        $params = [
            'oauth_consumer_key'     => $config['consumer_key'],
            'oauth_nonce'            => $nonce,
            'oauth_signature_method' => $config['signature_method'],
            'oauth_timestamp'        => time(),
        ];

        // Optional parameters should not be set if they have not been set in
        // the config as the parameter may be considered invalid by the Oauth
        // service.
        $optionalParams = [
            'callback'  => 'oauth_callback',
            'token'     => 'oauth_token',
            'verifier'  => 'oauth_verifier',
            'version'   => 'oauth_version'
        ];

        foreach ($optionalParams as $optionName => $oauthName) {
            if (isset($config[$optionName])) {
                $params[$oauthName] = $config[$optionName];
            }
        }

        return $params;
    }
}
