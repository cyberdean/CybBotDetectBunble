<?php

namespace Cyberdean\Security\BotDetectBundle\Event;


use Cyberdean\Security\BotDetectBundle\Entity\Security\Strike;
use Symfony\Component\EventDispatcher\Event;

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
    public function getStrike()  //todo remove and use read only methods
    {
        return $this->strike;
    }

}