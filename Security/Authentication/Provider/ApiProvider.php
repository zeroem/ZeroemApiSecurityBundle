<?php

namespace Zeroem\ApiSecurityBundle\Security\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\HttpFoundation\Request;

use Zeroem\ApiSecurityBundle\Security\Authentication\Token\ApiToken;
use Zeroem\ApiSecurityBundle\Notary\NotaryInterface;
use Zeroem\ApiSecurityBundle\Notary\GeneralNotary;

class ApiProvider implements AuthenticationProviderInterface
{
    private $userProvider;
    private $notary;

    public function __construct(UserProviderInterface $userProvider, NotaryInterface $notary) {
        $this->userProvider = $userProvider;
        $this->notary = $notary;
    }

    public function authenticate(TokenInterface $token) {
        if($this->supports($token) && $this->notary->canVerify($token->request)) {
            $user = $this->userProvider->loadUserByUsername(
                $this->notary->getUsername($token->request)
            );

            if($user && $this->notary->verify($user,$token->request)) {
                $authenticatedToken = new ApiToken($user->getRoles());
                $authenticatedToken->setUser($user);
                $authenticatedToken->request = $token->request;

                return $authenticatedToken;
            }
        } else {
            return null;
        }

        throw new AuthenticationException('The Api authentication failed.');
    }

    public function supports(TokenInterface $token) {
        return $token instanceof ApiToken;
    }
}