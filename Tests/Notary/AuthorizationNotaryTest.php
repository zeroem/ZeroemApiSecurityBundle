<?php

namespace Zeroem\ApiSecurityBundle\Tests\Notary;

use Zeroem\ApiSecurityBundle\Notary\GeneralNotary;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserInterface;

class AuthorizationNotaryTest extends \PHPUnit_Framework_Testcase
{

    public function testRequestSigning() {
        $request = Request::create("http://symfony.com");
        $request->headers->set("date",date("r"));

        $notary = new AuthorizationNotary();

        $notary->sign($this->getMockUserA(),$request);

        $this->assertNotEmpty($request->headers->get("authorization"));

        return $request;
    }

    /**
     * @depends testRequestSigning
     */
    public function testSignatureVerification(Request $request) {
        $notary = new AuthorizationNotary();

        $this->assertFalse($notary->verify($this->getMockUserB(),$request));
        $this->assertFalse($notary->verify($this->getMockImposterA(),$request));
        $this->assertTrue($notary->verify($this->getMockUserA(),$request));
    }

    private function makeMockUser($username,$password,$checkPass=true) {
        $user = $this->getMock(
            "\Symfony\Component\Security\Core\User\UserInterface", 
            array("getUsername","getPassword","getSalt","getRoles","eraseCredentials")
        );

        $user->expects($this->once())
            ->method("getUsername")
            ->will($this->returnValue($username));

        if($checkPass) {
            $user->expects($this->once())
                ->method("getPassword")
                ->will($this->returnValue($password));
        }

        return $user;
    }

    private function getMockUserA() {
        return $this->makeMockUser("user","password",true);
    }

    private function getMockUserB() {
        return $this->makeMockUser("resu","drowssap",false);
    }

    private function getMockImposterA() {
        return $this->makeMockUser("user","drowssap",true);
    }
}

