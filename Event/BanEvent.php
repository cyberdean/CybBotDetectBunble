<?php

namespace Cyberdean\Security\BotDetectBundle\Event;


use Cyberdean\Security\BotDetectBundle\Entity\Security\Ban;
use Symfony\Component\EventDispatcher\Event;

/**
 * Class BanEvent
 * When ip is banned, this event is sended in Symfony Event dispatcher
 * @package Cyberdean\Security\BotDetectBundle\Event
 */
class BanEvent extends Event
{
    const NAME = 'cyb.botdetect.security.ban';

    /* @var $ban Ban */
    protected $ban;

    /**
     * BanEvent constructor.
     * @param $ban Ban
     */
    public function __construct(Ban $ban)
    {
        $this->ban = $ban;
    }

    /**
     * @return Ban
     */
    public function getBan()
    {
        return $this->ban;
    }
}