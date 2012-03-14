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
        $apiUser = $this->userProvider->loadUserByUsername($token->apiToken);

        if($apiUser && $this->notary->verify($apiUser,$token->request)) {
            $authenticatedToken = new ApiToken($user->getRoles());
            $authenticatedToken->setUser($user);

            return $authenticatedToken;
        }

        throw new AuthenticationException('The Api authentication failed.');
    }

    public function supports(TokenInterface $token) {
        return $token instanceof ApiToken;
    }
}