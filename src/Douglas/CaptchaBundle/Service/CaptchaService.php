<?php


namespace App\Douglas\CaptchaBundle\Service;


use App\Douglas\CaptchaBundle\Event\CaptchaBadRequestEvent;
use App\Douglas\CaptchaBundle\Event\CaptchaFailEvent;
use App\Douglas\CaptchaBundle\Event\CaptchaRobotEvent;
use App\Douglas\CaptchaBundle\Event\CaptchaSuccessEvent;
use GuzzleHttp\Client;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;


class CaptchaService
{
    private CONST GOOGLE_URL = 'https://www.google.com/recaptcha/api/siteverify';

    private $dispatcher;

    public function __construct(EventDispatcherInterface $dispatcher) {
        $this->dispatcher = $dispatcher;
    }

    public function checkCaptcha($captchaToken, $secretKey, $action, $threshold): bool
    {
        $data = ['secret' => $secretKey, 'response' => $captchaToken];
        $client = new Client();
        $captchaSuccess = false;
        try {
            $response = json_decode($client->request('POST', self::GOOGLE_URL, ['form_params' => $data])->getBody()->getContents());
            if ($response->success) {
                if ($response->action == $action && $response->score > $threshold) {
                    $captchaSuccess = true;
                    $this->dispatcher->dispatch(new CaptchaSuccessEvent($response));
                } else {
                    $this->dispatcher->dispatch(new CaptchaRobotEvent($response));
                }
            } else {
                $this->dispatcher->dispatch(new CaptchaFailEvent($response));
            }
        } catch (\Exception $e ) {
            $this->dispatcher->dispatch(new CaptchaBadRequestEvent($e->getMessage()));
        }

        return $captchaSuccess;
    }
}