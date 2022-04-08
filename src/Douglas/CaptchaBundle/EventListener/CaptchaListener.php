<?php


namespace App\Douglas\CaptchaBundle\EventListener;


use App\Douglas\CaptchaBundle\Event\CaptchaBadRequestEvent;
use App\Douglas\CaptchaBundle\Event\CaptchaFailEvent;
use App\Douglas\CaptchaBundle\Event\CaptchaRobotEvent;
use App\Douglas\CaptchaBundle\Event\CaptchaSuccessEvent;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;

class CaptchaListener
{
    private $logger;

    public function __construct(LoggerInterface $appLogger){
        $this->logger = $appLogger;
    }

    public function onCaptchaRobot(CaptchaRobotEvent $event){
        $request = Request::createFromGlobals();
        $ip = $request->server->get('REMOTE_ADDR');
        $response = $event->getResponse();
        $this->logger->info($ip . ": client was detected as robot, action was " . $response->action . ", score was " . $response->score);
    }

    public function onCaptchaFail(CaptchaFailEvent $event){
        $request = Request::createFromGlobals();
        $ip = $request->server->get('REMOTE_ADDR');
        $response = $event->getResponse();
        $response = json_decode(json_encode($response), true);
        $this->logger->info($ip . ": request to captcha failed, errors was " . implode(', ', $response['error-codes']));
    }

    public function onCaptchaBadRequest(CaptchaBadRequestEvent $event){
        $request = Request::createFromGlobals();
        $ip = $request->server->get('REMOTE_ADDR');
        $message = $event->getMessage();
        $this->logger->info($ip . ": request to captha has thrown Exception, message was ". $message);
    }

    public function onCaptchaSuccess(CaptchaSuccessEvent $event){
        $request = Request::createFromGlobals();
        $ip = $request->server->get('REMOTE_ADDR');
        $response = $event->getResponse();
        $this->logger->info($ip . ": captcha succeded, action was " . $response->action . ", score was " . $response->score);
    }
}