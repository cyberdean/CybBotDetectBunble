<?php
namespace Cyberdean\Security\BotDetectBundle\Listener;


use Cyberdean\Security\BotDetectBundle\Manager\BotDetectManager;
use Cyberdean\Security\BotDetectBundle\Manager\ConfigManager;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Templating\EngineInterface;

class KernelRequestListener {
    private $manager;
    private $config;
    private $twig;

    public function __construct(BotDetectManager $manager, EngineInterface $twig, ConfigManager $config) {
        $this->manager = $manager;
        $this->twig = $twig;
        $this->config = $config;
    }

    public function onKernelRequest(GetResponseEvent $event) {
        $request   = $event->getRequest();

        if ($this->manager->check($request->getClientIp())) {
            $tpl = $this->twig->render('CybBotDetectBundle::userBanned.html.twig', array('ip' => $request->getClientIp()));
            $event->setResponse(new Response($tpl), $this->config->getBannedResponseCode());
            $event->stopPropagation();
            return;
        }

        $this->manager->process($request);
    }
}