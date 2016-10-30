<?php

namespace Cyberdean\Security\BotDetectBundle\Event;


use Symfony\Component\EventDispatcher\Event;

class BanEvent extends Event
{
    const NAME = 'cyb.botdetect.security.ban';

    /* @var $ip string */
    protected $ip;

    /**
     * BanEvent constructor.
     * @param $ip string
     */
    public function __construct($ip)
    {
        $this->ip = $ip;
    }

    /**
     * @return mixed
     */
    public function getIp()
    {
        return $this->ip;
    }



}