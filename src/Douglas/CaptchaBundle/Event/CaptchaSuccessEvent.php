<?php


namespace App\Douglas\CaptchaBundle\Event;


use Symfony\Contracts\EventDispatcher\Event;

/**
 * Class CaptchaSuccessEvent
 * @package App\Douglas\CaptchaBundle\Event
 * Вызывается, если капча успешно пройдена
 */
class CaptchaSuccessEvent extends Event
{
    public const NAME = 'captcha.success';

    private $response;

    public function __construct($response) {
        $this->response = $response;
    }

    public function getResponse() {
        return $this->response;
    }
}