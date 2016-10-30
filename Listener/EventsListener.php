<?php

namespace Cyberdean\Security\BotDetectBundle\Listener;

use Cyberdean\Security\BotDetectBundle\Entity\Security\Ban;
use Cyberdean\Security\BotDetectBundle\Entity\Security\Strike;
use Cyberdean\Security\BotDetectBundle\Event\BanEvent;
use Cyberdean\Security\BotDetectBundle\Event\StrikeEvent;
use Doctrine\ORM\Event\LifecycleEventArgs;
use Symfony\Bridge\Monolog\Logger;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

class EventsListener
{
    private $eventDispatcher;
    private $logger;

    public function __construct(EventDispatcherInterface $eventDispatcher, Logger $logger)
    {
        $this->eventDispatcher = $eventDispatcher;
        $this->logger = $logger;
    }

    public function prePersist(LifecycleEventArgs $event) {
        $entity = $event->getEntity();
        if ($entity instanceof Strike) {
            $this->eventDispatcher->dispatch(StrikeEvent::NAME, new StrikeEvent($entity));
        }
        else if($entity instanceof Ban) {
            $this->eventDispatcher->dispatch(BanEvent::NAME, new BanEvent($entity->getIp()));
        }
        else {
            $this->logger->error('[CybBotDetectBundle] Fail to dispatch unknown entity type event : ' . var_export($entity, true));
        }
    }
}