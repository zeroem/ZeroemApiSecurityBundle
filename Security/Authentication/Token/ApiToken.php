<?php

namespace Zeroem\ApiSecurityBundle\Security\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class ApiToken extends AbstractToken
{
    public $request;

    public function getCredentials() {
        return "";
    }
}