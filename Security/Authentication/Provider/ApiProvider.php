namespace Zeroem\ApiSecurityBundle\Security\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\HttpFoundation\Request;

use Zeroem\ApiSecurityBundle\Security\Authentication\Token\ApiToken;

class ApiProvider implements AuthenticationProviderInterface
{
    private $userProvider;

    private static $requiresContentMd5 = array("POST","PUT","PATCH");

    public function __construct(UserProviderInterface $userProvider) {
        $this->userProvider = $userProvider;
    }

    public function authenticate(TokenInterface $token) {
        $apiUser = $this->userProvider->loadUserByUsername($token->apiToken);

        if($apiUser && $this->validateRequest($token->request, $user, $token->signature)) {
            $authenticatedToken = new ApiToken($user->getRoles());
            $authenticatedToken->setUser($user);

            return $authenticatedToken;
        }

        throw new AuthenticationException('The Api authentication failed.');
    }

    protected function validateRequest(Request $request, UserInterface $user, $providedSignature) {

        // Enforce a time limit on the request
        if(!$this->isValidTimestamp(strtotime($request->headers->get("date")))) {
            return false;
        }
        
        $parts = array()
        $parts[] = $request->getMethod();
        if($request->headers->has("content-md5")) {
            $parts[] = $request->headers->get("content-md5");
        } else if(in_array($request->getMethod(),self::$requiresContentMd5)) {
            return false;
        }

        $parts[] = $request->headers->get("date");
        $parts[] = $this->makeResource($request);

        $message = implode("\n",$parts);

        $calculatedSignature = hash_hmac("sha256",$message,$user->getPassword());

        return $calculatedSignature == $providedSignature;
    }

    protected function isValidTimestamp($timestamp) {
        return false !== $timestamp && (abs(time() - $timestamp) < 300);
    }

    protected function makeResource(Request $request) {
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

    public function supports(TokenInterface $token) {
        return $token instanceof ApiToken;
    }
}