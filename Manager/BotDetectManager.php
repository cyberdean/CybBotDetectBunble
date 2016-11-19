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
use Symfony\Component\HttpFoundation\Response;
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

    /**
     * Determine if bot or not
     * @param $userAgent string UserAgent to test
     * @return false|\Cyberdean\Security\BotDetectBundle\Entity\Security\BadUserAgent
     */
    public function isBot($userAgent) {
        $badUserAgentRepo = $this->em->getRepository('CybBotDetectBundle:Security\BadUserAgent');
        return $badUserAgentRepo->matchUA(trim(strtolower($userAgent))) != null;
    }

    /**
     * Check if an ip address can access or should be blocked (= is banned)
     * @param $ip string User ip address
     * @return bool True is request should be blocked, false otherwise
     */
    public function check($ip) {
        $ban = $this->banRepo->getCurrentIpBan($ip);
        return isset($ban);
    }

    public function checkUrl(Request $request) {
        $url = strtolower($request->getRequestUri());

        //remove /app_dev.php
        if (substr($url, 0, 12) == '/app_dev.php') { //remove leading slash
            $url = substr($url, 12, strlen($url));
        }

        //remove /app.php
        if (substr($url, 0, 8) == '/app.php') { //remove leading slash
            $url = substr($url, 8, strlen($url));
        }

        $badUrlRepo = $this->em->getRepository('CybBotDetectBundle:Security\BadUrl');
        return array($badUrlRepo->matchUrl($url) != null, $url);
    }

    /**
     * Inspect request to detect suspect user/bot
     * @param Request $request
     */
    public function process(Request $request) {
        $ip = $request->getClientIp();

        if ($this->config->isUaCheck()) {
            $ua = $request->headers->get('User-Agent');
            $res = $this->isBot($ua);
            if ($res) {
                $sk = new Strike();
                $sk->setIp($ip)
                    ->setDate(new \DateTime())
                    ->setReason(ReasonEnum::UA)
                    ->setReasonDetails(json_encode(array('original' => $ua, 'match' => $res->getUa())));
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
            $request->getSession()->set('banned', true);
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
        $lastBan = $this->banRepo->findOneBy(array('ip' => $ip), array('endBan' => 'desc'));
        $date = new \DateTime();
        $di = new \DateInterval('P15D');//todo make configurable

        if ($lastBan && $lastBan->getEndBan()->diff($date)->days < $di->days) {
            $date = $lastBan->getEndBan();
        }
        else {
            $date->sub($di);
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
                    return $count > 10;
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