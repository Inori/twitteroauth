<?php
namespace Inori\TwitterOAuth\OAuth;

abstract class OAuthSignatureMethod
{
    /**
     * Needs to return the name of the Signature Method (ie HMAC-SHA1)
     *
     * @return string
     */
    abstract public function getName();

    /**
     * Build up the signature
     * NOTE: The output of this function MUST NOT be urlencoded.
     * the encoding is handled in OAuthRequest when the final
     * request is serialized
     *
     * @param  \Inori\TwitterOAuth\OAuth\OAuthRequest  $request
     * @param  \Inori\TwitterOAuth\OAuth\OAuthConsumer $consumer
     * @param  \Inori\TwitterOAuth\OAuth\OAuthToken    $token
     * @return string
     */
    abstract public function buildSignature(
        OAuthRequest $request,
        OAuthConsumer $consumer,
        OAuthToken $token = null
    );

    /**
     * Verifies that a given signature is correct
     *
     * @param  \Inori\TwitterOAuth\OAuth\OAuthRequest  $request
     * @param  \Inori\TwitterOAuth\OAuth\OAuthConsumer $consumer
     * @param  \Inori\TwitterOAuth\OAuth\OAuthToken    $token
     * @param  string                                  $signature
     * @return bool
     */
    public function checkSignature(
        OAuthRequest $request,
        OAuthConsumer $consumer,
        OAuthToken $token = null,
        $signature
    ) {
        $built = $this->buildSignature($request, $consumer, $token);

        return $built == $signature;
    }
}
