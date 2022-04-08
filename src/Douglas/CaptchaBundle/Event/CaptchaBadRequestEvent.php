<?php


namespace App\Douglas\CaptchaBundle\Event;


use Symfony\Contracts\EventDispatcher\Event;

/**
 * Class CaptchaBadRequestEvent
 * @package App\Douglas\CaptchaBundle\Event
 * Вызывается, если запрос к серверу капчи вызвал исключение (например, при ошибке http)
 */
class CaptchaBadRequestEvent extends Event
{
    public const NAME = 'captcha.bad.request';

    private $message;

    public function __construct($message) {
        $this->message = $message;
    }

    public function getMessage() {
        return $this->message;
    }
}