<?php

namespace Zeroem\ApiSecurityBundle\Notary;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserInterface;


interface NotaryInterface
{
    /**
     * Transform the given request into a signed request.
     * 
     * @param Request $request The request to be signed
     * @return boolean Whether or not the signature succeeded
     */
    function sign(UserInterface $signator, Request $request);

    /**
     * Verify whether or not the signature on the request is valid
     * 
     * @param Request $request The request to verify
     * @return boolean Whether or not the signature is valid
     */
    function verify(UserInterface $signator, Request $request);
}

