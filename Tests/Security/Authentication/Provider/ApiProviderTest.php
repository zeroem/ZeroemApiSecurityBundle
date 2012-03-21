<?php

namespace Zeroem\ApiSecurityBundle\Tests\Security\Authentication\Provider;

use Zeroem\ApiSecurityBundle\Security\Authentication\Provider\ApiProvider;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\HttpFoundation\Request;

class ApiProviderTest extends \PHPUnit_Framework_Testcase
{

    public function testPassingVerifcation() {
        $user = $this->makeMockUser();
        $provider = new ApiProvider(
            $this->getUserProvider($user),
            $this->getNotary($user,true)
        );

        $this->assertInstanceOf('\Zeroem\ApiSecurityBundle\Security\Authentication\Token\ApiToken', $provider->authenticate($this->getAuthenticationToken()));
    }

    /**
     * @expectedException \Symfony\Component\Security\Core\Exception\UsernameNotFoundException
     */
    public function testUserDoesNotExist() {
        $user = $this->makeMockUser();
        $provider = new ApiProvider(
            $this->getUserProvider(),
            $this->getNotary($user,true)
        );

        $provider->authenticate($this->getAuthenticationToken());
    }

    /**
     * @expectedException \Symfony\Component\Security\Core\Exception\AuthenticationException
     */
    public function testCannotVerifyRequest() {
        $user = $this->makeMockUser();
        $provider = new ApiProvider(
            $this->getUserProvider($user),
            $this->getNotary($user,true,false)
        );

        $provider->authenticate($this->getAuthenticationToken());
    }

    /**
     * @expectedException Symfony\Component\Security\Core\Exception\AuthenticationException
     */
    public function testFailedAuthentication() {
        $user = $this->makeMockUser();
        $provider = new ApiProvider(
            $this->getUserProvider($user),
            $this->getNotary($user,false)
        );

        $provider->authenticate($this->getAuthenticationToken());
    }

    private function getAuthenticationToken() {
        $token = $this->getMock(
            'Zeroem\ApiSecurityBundle\Security\Authentication\Token\ApiToken',
            array()
        );

        $token->request = new Request();

        return $token;
    }

    private function makeMockUser() {
        $user = $this->getMock(
            'Symfony\Component\Security\Core\User\UserInterface',
            array("getUsername","getPassword","getSalt","getRoles","eraseCredentials")
        );

        $user->expects($this->any())
            ->method("getUsername")
            ->will($this->returnValue("user"));

        $user->expects($this->any())
            ->method("getRoles")
            ->will($this->returnValue(array("ROLE_FOO")));

        return $user;
    }

    private function getUserProvider(UserInterface $user=null) {
        $provider = $this->getMock(
            'Symfony\Component\Security\Core\User\UserProviderInterface',
            array("loadUserByUsername","refreshUser","supportsClass")
        );
        
        if(isset($user)) {
            $provider->expects($this->any())
                ->method("loadUserByUsername")
                ->will($this->returnValue($user));
        } else {
            $provider->expects($this->any())
                ->method("loadUserByUsername")
                ->will($this->throwException(new \Symfony\Component\Security\Core\Exception\UsernameNotFoundException("derp")));
        }
        return $provider;
    }

    private function getNotary(UserInterface $user, $success=true, $canVerify=true) {
        $notary = $this->getMock(
            "Zeroem\ApiSecurityBundle\Notary\GeneralNotary",
            array("verify","canVerify","getUsername")
        );

        $notary->expects($this->any())
            ->method("verify")
            ->will($this->returnValue($success));

        $notary->expects($this->any())
            ->method("canVerify")
            ->will($this->returnValue($canVerify));

        $notary->expects($this->any())
            ->method("getUsername")
            ->will($this->returnValue($user->getUsername()));

        return $notary;
    }
}
