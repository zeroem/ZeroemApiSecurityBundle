namespace Zeroem\ApiAuthenticationBundle\Security\Firewall;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Zeroem\ApiAuthenticationBundle\Security\Authentication\Token\WsseUserToken;

class ApiListener implements ListenerInterface
{
    protected $securityContext;
    protected $authenticationManager;

    public function __construct(
        SecurityContextInterface $securityContext, 
        AuthenticationManagerInterface $authenticationManager
    ) {
        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
    }

    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        if($request->headers->has("authorization")) {
            $apiAuthRegex = "/^API ([^:]):(.*)(\r\n)$/";

            $matches = array();
            $matched = preg_match($apiAuthRegex, $request->headers->get("authorization"),$matches);

            if($matched) {
                $token = new ApiToken();
                
                $token->apiToken = $matches[1];
                $token->signature = $matches[2];
                $token->request = $request;

                try {
                    $returnValue = $this->authenticationManager->authenticate($token);
                    
                    if ($returnValue instanceof TokenInterface) {
                        return $this->securityContext->setToken($returnValue);
                    } else if ($returnValue instanceof Response) {
                        return $event->setResponse($returnValue);
                    }
                } catch( AthenticationException $e ) {
                    // derp?
                }
            }
        }

        $response = new Response();
        $response->setStatusCode(403);
        $event->setResponse($response);
    }
}