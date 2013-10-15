<?php

/*
 * This file is part of the FOSOAuthServerBundle package.
 *
 * (c) FriendsOfSymfony <http://friendsofsymfony.github.com/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FOS\OAuthServerBundle\Security\Authentication\Provider;

use FOS\OAuthServerBundle\Model\AccessTokenInterface;
use FOS\OAuthServerBundle\Security\Authentication\Token\OAuthToken;
use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\AccountStatusException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserCheckerInterface;

use OAuth2\OAuth2;
use OAuth2\OAuth2ServerException;
use OAuth2\OAuth2AuthenticateException;

/**
 * OAuthProvider class.
 *
 * @author  Arnaud Le Blanc <arnaud.lb@gmail.com>
 */
class OAuthProvider implements AuthenticationProviderInterface
{
    /**
     * @var UserProviderInterface
     */
    protected $userProvider;
    /**
     * @var OAuth2
     */
    protected $serverService;
    /**
     * @var UserCheckerInterface
     */
    protected $userChecker;

    /**
     * @param UserProviderInterface $userProvider      The user provider.
     * @param OAuth2 $serverService The OAuth2 server service.
     * @param UserCheckerInterface $userChecker
     */
    public function __construct(UserProviderInterface $userProvider, OAuth2 $serverService, UserCheckerInterface $userChecker)
    {
        $this->userProvider  = $userProvider;
        $this->serverService = $serverService;
        $this->userChecker = $userChecker;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            return null;
        }

        /* @var $token OAuthToken */
        try {
            $tokenString = $token->getToken();

            if ($accessToken = $this->serverService->verifyAccessToken($tokenString)) {
                /* @var $accessToken AccessTokenInterface */
                $scope = $accessToken->getScope();
                $user  = $accessToken->getUser();

                if (true === $token->isAuthenticated()) { // ContextListener retrieved token from the session and already refreshed user object
                    $user = $token->getUser(); // we don't need to refresh user again, so we just pull user object from the authenticated token
                } else {
                    $user = $this->userProvider->refreshUser($user); // let's refresh user
                }

                $roles = (null !== $user) ? $user->getRoles() : array();

                if (!empty($scope)) {
                    foreach (explode(' ', $scope) as $role) {
                        $roles[] = 'ROLE_' . strtoupper($role);
                    }
                }

                $token = new OAuthToken($roles);
                $token->setAuthenticated(true);
                $token->setToken($tokenString);

                if (null !== $user) {

                    try {
                        $this->userChecker->checkPostAuth($user);
                    } catch (AccountStatusException $e) {
                        throw new OAuth2AuthenticateException(OAuth2::HTTP_UNAUTHORIZED,
                            OAuth2::TOKEN_TYPE_BEARER,
                            $this->serverService->getVariable(OAuth2::CONFIG_WWW_REALM),
                            'access_denied',
                            $e->getMessage()
                        );
                    }

                    $token->setUser($user);
                }

                return $token;
            }
        } catch (OAuth2ServerException $e) {
            if (!method_exists('Symfony\Component\Security\Core\Exception\AuthenticationException', 'setToken')) {
                // Symfony 2.1
                throw new AuthenticationException('OAuth2 authentication failed', null, 0, $e);
            }
            
            throw new AuthenticationException('OAuth2 authentication failed', 0, $e);
        }

        throw new AuthenticationException('OAuth2 authentication failed');
    }

    /**
     * {@inheritdoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof OAuthToken;
    }
}
