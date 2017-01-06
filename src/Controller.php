<?php
namespace bhubr\SlimUser;

use Slim\Csrf\Guard;
use Slim\Views\Twig;
use Psr\Log\LoggerInterface;
use Illuminate\Database\Query\Builder;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;
use bhubr\SlimUser\User;
use Respect\Validation\Validator as v;
use Sabre\Event\EventEmitter;

/**
 * Controller for handling user-related stuff:
 *   - registration
 *   - authentication
 *   - password loss/reset
 *
 * Todo:
 *   - add middleware for session checking
 */
class Controller
{
    /**
     * Twig view instance
     */
    private $view;

    /**
     * Logger instance
     */
    private $logger;

    /**
     * Csrf Guard instance
     */
    private $csrf;

    /**
     * Sabre library's EventEmitter instance
     */
    private $emitter;

    /**
     * Constructor
     */
    public function __construct(
        Guard $csrf,
        Twig $view,
        LoggerInterface $logger,
        EventEmitter $emitter
    ) {
        $this->csrf = $csrf;
        $this->view = $view;
        $this->logger = $logger;
        $this->emitter = $emitter;
    }

    /**
     * Return template path to add it to Twig View's paths
     */
    public static function getTemplatePath() {
        return realpath(__DIR__ . '/../templates');
    }

    /**
     * Sign up page
     */
    public function getSignup(Request $request, Response $response, $args)
    {
        // CSRF token name and value
        $name = $request->getAttribute('csrf_name');
        $value = $request->getAttribute('csrf_value');

        $this->view->render($response, 'user/signup.twig', [
            'csrfName' => $name,
            'csrfValue' => $value
        ]);
        return $response;
    }

    /**
     * Process sign up form
     */
    public function postSignup(Request $request, Response $response, $args)
    {
        // In case we need to redirect
        $signupUri = $request->getUri()->withPath('/auth/signup');

        // Get POSTed attributes
        $attributes = $request->getParsedBody();

        // Attributes validation
        if( !v::email()->validate( $attributes['email'] ) ) {
            return $response = $response->withRedirect($signupUri, 403);
        }
        if( !v::stringType()->length(8, null)->validate( $attributes['password'] ) ) {
            return $response = $response->withRedirect($signupUri, 403);
        }

        // Password hashing
        $attributes['password'] = password_hash( $attributes['password'], PASSWORD_BCRYPT );

        try {
            $user = User::create($attributes);
            $this->emitter->emit('user:signin', [$user]);
            $session = new \RKA\Session();
            $session->set('user', $user);
        } catch( \Exception $e ) {
            die( $e->getCode() );
        }
        $uri = $request->getUri()->withPath('/');
        return $response = $response->withRedirect($uri); //, 403);
    }

    /**
     * Sign in page
     */
    public function getSignin(Request $request, Response $response, $args)
    {
        // CSRF token name and value
        $name = $request->getAttribute('csrf_name');
        $value = $request->getAttribute('csrf_value');

        $this->view->render($response, 'user/signin.twig', [
            'csrfName' => $name,
            'csrfValue' => $value
        ]);
        return $response;
    }

    /**
     * Process sign in form
     */
    public function postSignin(Request $request, Response $response, $args)
    {
        $signinUri = $request->getUri()->withPath('/auth/signin');
        $credentials = $request->getParsedBody();

        if( !v::email()->validate( $credentials['email'] ) ) {
            return $response = $response->withRedirect($signinUri, 403);
        }

        $user = User::where(['email' => $credentials['email']])->first();

        if ( is_null( $user ) ) {
            return $response = $response->withRedirect($signinUri, 403);
        }

        if ( ! password_verify ($credentials['password'], $user->password ) ) {
            return $response = $response->withRedirect($signinUri, 403);
        }
        $homeUri = $request->getUri()->withPath('/');

        $session = new \RKA\Session();
        $session->set('user', $user);

        return $response = $response->withRedirect($homeUri);

    }

    /**
     * Sign out and destroy session
     */
    public function getSignout(Request $request, Response $response, $args)
    {
        \RKA\Session::destroy();
        $homeUri = $request->getUri()->withPath('/');
        return $response = $response->withRedirect($homeUri);
    }
}