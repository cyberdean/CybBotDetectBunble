<?php

namespace Cyberdean\Security\BotDetectBundle\Listener;


use Cyberdean\Security\BotDetectBundle\Entity\Security\Strike;
use Cyberdean\Security\BotDetectBundle\Manager\BotDetectManager;
use Cyberdean\Security\BotDetectBundle\Manager\ConfigManager;
use Cyberdean\Security\BotDetectBundle\ReasonEnum;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;

class KernelResponseListener {
    private $em;
    private $config;
    private $manager;

    public function __construct(EntityManagerInterface $em, ConfigManager $config, BotDetectManager $manager) {
        $this->em = $em;
        $this->config = $config;
        $this->manager = $manager;
    }

    public function onKernelResponse(FilterResponseEvent $event)
    {
        $response = $event->getResponse();
        $request = $event->getRequest();

        if (!$request->getSession()->get('banned', false)) {
            if ($this->config->isErr404Check() && $response->getStatusCode() == 404) {
                //todo check if this request has suspect URL strike ??? (If not one request can add multiple strike for differants reasons)
                $sk = new Strike();
                $sk->setIp($request->getClientIp());
                $sk->setDate(new \DateTime());
                $sk->setReason(ReasonEnum::ERR404);
                $sk->setReasonDetails($request->getRequestUri());
                $this->em->persist($sk);
                $this->em->flush();
            }
            else if ($this->config->isErr4xxCheck() && $response->getStatusCode() != 404 && $response->getStatusCode() >= 400 && $response->getStatusCode() < 500) {
                $sk = new Strike();
                $sk->setIp($request->getClientIp());
                $sk->setDate(new \DateTime());
                $sk->setReason(ReasonEnum::ERR4XX);
                $sk->setReasonDetails($request->getRequestUri());
                $this->em->persist($sk);
                $this->em->flush();
            }
        }
        $request->getSession()->remove('banned');
    }
}