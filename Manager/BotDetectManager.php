<?php

namespace Cyberdean\Security\BotDetectBundle\Manager;


use Cyberdean\Security\BotDetectBundle\Entity\Security\Ban;
use Cyberdean\Security\BotDetectBundle\Entity\Security\Strike;
use Cyberdean\Security\BotDetectBundle\ReasonEnum;
use Doctrine\ORM\EntityManager;
use Symfony\Bridge\Monolog\Logger;
use Symfony\Bundle\FrameworkBundle\Routing\Router;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Exception\MethodNotAllowedException;
use Symfony\Component\Routing\Exception\ResourceNotFoundException;

class BotDetectManager {
    private $em;
    private $config;
    private $logger;
    private $eventDispatcher;
    private $router;

    private $banRepo;
    private $strikeRepo;

    public function __construct(EntityManager $entityManager, ConfigManager $config, Logger $logger,
                                EventDispatcherInterface $eventDispatcher, Router $router) {
        $this->em = $entityManager;
        $this->banRepo = $this->em->getRepository('CybBotDetectBundle:Security\Ban');
        $this->strikeRepo = $this->em->getRepository('CybBotDetectBundle:Security\Strike');
        $this->config = $config;
        $this->logger = $logger;
        $this->eventDispatcher = $eventDispatcher;
        $this->router = $router;
    }

    public function isBot($userAgent) {
        //todo use regex ??
        $badUserAgentRepo = $this->em->getRepository('CybBotDetectBundle:Security\BadUserAgent');
        return $badUserAgentRepo->findOneBy(array('ua' => $userAgent)) != null;
    }

    /**
     * Check if an ip address can access or should be blocked
     * @param $ip string User ip address
     * @return bool True is request should be blocked, false otherwise
     */
    public function check($ip) {
        $ban = $this->banRepo->getCurrentIpBan($ip);
        return isset($ban);
    }

    public function checkUrl(Request $request) {
        $url = strtolower($request->getRequestUri());
        if (substr($url, -1) == '/') { //remove leading slash
            $url = substr($url, 0, strlen($url)-1);
        }
        //strip params
        $url = strtok($url, '?');
        $url = strtok($url, '#');

        //remove .php at end
        $ext = array('.php' => 4, '.html' => 5);
        foreach ($ext as $e => $length) {
            if (substr($url, -$length) == $e) {
                $url = substr($url, 0, strlen($url)-$length);
                break;
            }
        }

        $badUrlRepo = $this->em->getRepository('CybBotDetectBundle:Security\BadUrl');
        return $badUrlRepo->findOneBy(array('url' => $url)) != null;
    }

    /**
     * Inspect request to detect suspect user/bot
     * @param Request $request
     */
    public function process(Request $request) {
        $ip = $request->getClientIp();
        if ($this->check($ip)) return;  //todo use array  clientIps

        $ua = $request->headers->get('User-Agent');
        if ($this->isBot($ua)) {
            $sk = new Strike();
            $sk->setIp($ip)
                ->setDate(new \DateTime())
                ->setReason(ReasonEnum::UA)
                ->setReasonDetails($ua);
            $this->em->persist($sk);
            $this->em->flush();
        }

        $matchToExistingUrl = false;
        try {
            $matcher = $this->router->getMatcher();
            $matcher->match($request->getRequestUri());
            $matchToExistingUrl = true;
        }
        catch (ResourceNotFoundException $e) {
        }
        catch (MethodNotAllowedException $e) {
        }

        //todo maybe a problem with dynamic routers ???  --> Second check on 4xx response ??
        if ($matchToExistingUrl) {
            //check suspect url, if not match existing route
            $urlRes = $this->checkUrl($request);
            if ($urlRes[0]) {
                $sk = new Strike();
                $sk->setIp($ip)
                    ->setDate(new \DateTime())
                    ->setReason(ReasonEnum::URL)
                    ->setReasonDetails($urlRes[1]);
                $this->em->persist($sk);
                $this->em->flush();
            }
        }

        $strike = $this->isTooManyStrike($ip);
        if ($strike) {
            $ban = new Ban();
            $ban->setIp($ip)
                ->setStartBan(new \DateTime())
                ->setEndBan($this->getBanEndTime($ip))
                ->setReason(null);
            $this->em->persist($ban);
            $this->em->flush();
        }
    }

    /**
     * Get date of end ban (progressive)
     * @param $ip string Evil ip
     * @return \DateTime
     */
    public function getBanEndTime($ip) {
        $banArray = $this->banRepo->findBy(array('ip' => $ip), array('startBan' => 'desc'));
        $end = new \DateTime();

        if ($banArray) {
            if (count($banArray) > 5) {
                try {
                    $end->add(new \DateInterval($this->config->getMaxBanInterval()));
                }
                catch (\Exception $e) {
                    $end->add(new \DateInterval('P6M'));
                    $this->logger->error('[CybBotDetectBundle] Fail to parse MaxBanInterval in config.yml -> must be valid string DateInterval interval_spec');
                }
                return $end; // ~ infinite ban
            }

            /* @var $diff \DateInterval */
            $diff = $banArray[0]->getStartBan()->diff($banArray[0]->getEndBan());
            if ($diff) {
                $end->add($diff)->add($diff);
                return $end;
            }
            else {
                $this->logger->error('[CybBotDetectBundle] Fail to get diff() between "' .
                    var_export($banArray[0]->getStartBan(), true) . '"" and "' . $banArray[0]->getEndBan() . '"');
            }
        }

        try {
            $end->add(new \DateInterval($this->config->getMinBanInterval()));
        }
        catch (\Exception $e) {
            $end->add(new \DateInterval('P3D'));
            $this->logger->error('[CybBotDetectBundle] Fail to parse MinBanInterval in config.yml -> must be valid string DateInterval interval_spec');
        }
        return $end;
    }

    /**
     * Check if an ip has too many strikes
     * @param $ip
     * @return bool True is has too many strike
     */
    public function isTooManyStrike($ip) {
        $lastBan = $this->banRepo->findOneBy(array('ip' => $ip), array('startBan' => 'desc'));
        if ($lastBan) {
            $date = $lastBan->getEndBan();
        }
        else {
            $date = new \DateTime();
            $date->sub(new \DateInterval('P1M')); //todo make configurable
        }

        $strikesCountArray = $this->strikeRepo->getStrikesSince($ip, $date);
        foreach ($strikesCountArray as $strikeType) {  //todo make more configurable
            $count = $strikeType['cpt'];
            switch ($strikeType['reason']) {
                case ReasonEnum::ERR404:
                    return $count > 200;
                    break;
                case ReasonEnum::ERR4XX:
                    return $count > 50;
                    break;
                case ReasonEnum::UA:
                    return $count > 1;
                    break;
                case ReasonEnum::URL:
                    return $count > 5;
                    break;
                default:
                case ReasonEnum::CUSTOM:
                    return $count > 10; //todo event ?
                    break;
            }
        }
        return false;
    }
}