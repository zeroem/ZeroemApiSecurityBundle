<?php

namespace Zeroem\ApiSecurityBundle\Notary;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserInterface;


class GeneralNotary implements NotaryInterface
{
    private static $authRegex = "/^API ([^:]*):(.*)(\r\n)?$/";
    private static $requiresContentMd5 = array("POST","PUT","PATCH");


    public function getUsername(Request $request) {
        $parts = array();
        if(preg_match(self::$authRegex,$request->headers->get("authorization"),$parts)) {
            return $parts[1];
        }

        return false;
    }

    public function canVerify(Request $request) {
        return $request->headers->has("authorization") && preg_match(self::$authRegex,$request->headers->get("authorization"));
    }

    public function sign(UserInterface $signator, Request $request) {
        $signature = $this->makeSignature($signator,$request);

        if(false !== $signature) {
            $request->headers->set("authorization","API {$signator->getUsername()}:{$signature}");
            return true;
        }

        return false;
    }

    private function makeSignature(UserInterface $signator, Request $request) {
        
        $parts = array();
        $parts[] = $request->getMethod();
        if($request->headers->has("content-md5")) {
            $parts[] = $request->headers->get("content-md5");
        } else if(in_array($request->getMethod(),self::$requiresContentMd5)) {
            return false;
        }

        $parts[] = $request->headers->get("date");
        $parts[] = $this->makeResource($request);

        $message = implode("\n",$parts);

        return $calculatedSignature = hash_hmac("sha256",$message,$signator->getPassword());                
    }

    /**
     * Was the request made within the last 5 minutes?
     * 
     * @param integer $timestamp unix timestamp
     * @return boolean
     */
    protected function isValidTimestamp(\DateTime $date) {
        return  (abs(time() - $date->getTimestamp()) < 300);
    }

    /**
     * Generate a properly formed "Resource" URL
     * 
     * @param Request $request
     */
    private function makeResource(Request $request) {
        $resource = $request->getBaseUrl();

        $queryArray = $request->query->all();
        if(!empty($queryArray)) {
            ksort($queryArray,SORT_STRING);
            $params = "";
            foreach($queryArray as $key=>$value) {
                if(!empty($params)) {
                    $params .= "&";
                }

                $params .= "{$key}={$value}";
            }

            $resource .= "?{$params}";
        }

        return $resource;
    }

    public function verify(UserInterface $signator, Request $request) {
        // Enforce a time limit on the request
        if(!$this->isValidTimestamp($request->headers->getDate("date"))) {
            return false;
        }

        $parts = array();
        if(preg_match(self::$authRegex,$request->headers->get("authorization"),$parts)) {
            $requestUser = $parts[1];
            $requestSignature = $parts[2];
            
            if($requestUser == $signator->getUsername()) {
                $calculatedSignature = $this->makeSignature($signator,$request);

                if($calculatedSignature == $requestSignature) {
                    return true;
                }
            }
        }

        return false;
    }
}

