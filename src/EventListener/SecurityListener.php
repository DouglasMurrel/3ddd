<?php


namespace App\EventListener;


use FOS\UserBundle\Event\FilterUserResponseEvent;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Event\AuthenticationFailureEvent;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;

class SecurityListener
{
    private $logger;
    private $security;

    public function __construct(LoggerInterface $appLogger, Security $security){
        $this->logger = $appLogger;
        $this->security = $security;
    }

    public function onLoginFailure(AuthenticationFailureEvent $event){
        $request = Request::createFromGlobals();
        $ip = $request->server->get('REMOTE_ADDR');
        $credentials = $event->getAuthenticationToken()->getCredentials();
        $this->logger->info($ip . ": login failure as " . $credentials['username']);
    }

    public function onLoginSuccess(InteractiveLoginEvent $event){
        $request = Request::createFromGlobals();
        $ip = $request->server->get('REMOTE_ADDR');
        $user = $this->security->getUser()->getUsername();
        $this->logger->info($ip . ": login success as " . $user);
    }

    public function onRegister(FilterUserResponseEvent $event){
        $request = Request::createFromGlobals();
        $ip = $request->server->get('REMOTE_ADDR');
        $user = $event->getUser()->getUsername();
        $this->logger->info($ip . ": user registered as " . $user);
    }
}