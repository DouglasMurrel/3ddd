<?php


namespace App\Douglas\CaptchaBundle\Event;


use Symfony\Contracts\EventDispatcher\Event;

/**
 * Class CaptchaRobotEvent
 * @package App\Douglas\CaptchaBundle\Event
 * Вызывается, если капча определила пользователя как робота
 */
class CaptchaRobotEvent extends Event
{
    public const NAME = 'captcha.robot';

    private $response;

    public function __construct($response) {
        $this->response = $response;
    }

    public function getResponse() {
        return $this->response;
    }
}