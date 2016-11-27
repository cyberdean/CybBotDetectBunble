<?php

namespace Cyberdean\Security\BotDetectBundle\Event;


use Cyberdean\Security\BotDetectBundle\Entity\Security\Strike;
use Symfony\Component\EventDispatcher\Event;

/**
 * Class StrikeEvent
 * When ip get a strike this event is sended, in Symfony Event Dispatcher
 * @package Cyberdean\Security\BotDetectBundle\Event
 */
class StrikeEvent extends Event
{
    const NAME = 'cyb.botdetect.security.strike';
    private $strike;

    /**
     * StrikeEvent constructor.
     * @param Strike $strike
     */
    public function __construct(Strike $strike)
    {
        $this->strike = $strike;
    }

    /**
     * @return Strike
     */
    public function getStrike()
    {
        return $this->strike;
    }

}