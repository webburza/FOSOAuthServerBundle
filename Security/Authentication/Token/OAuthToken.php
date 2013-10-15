<?php

/*
 * This file is part of the FOSOAuthServerBundle package.
 *
 * (c) FriendsOfSymfony <http://friendsofsymfony.github.com/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FOS\OAuthServerBundle\Security\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

/**
 * OAuthToken class.
 *
 * @author Arnaud Le Blanc <arnaud.lb@gmail.com>
 */
class OAuthToken extends AbstractToken
{
    const TOKEN_ATTRIBUTE_NAME = '__oauth_token';

    public function setToken($token)
    {
        // token string MUST be serializable, storing it as an attribute is the easiest way to achieve that
        $this->setAttribute(self::TOKEN_ATTRIBUTE_NAME, $token);
    }

    public function getToken()
    {
        try {
            return $this->getAttribute(self::TOKEN_ATTRIBUTE_NAME);
        } catch (\InvalidArgumentException $e) {
            return null;
        }
    }

    public function getCredentials()
    {
        return $this->getToken();
    }
}
