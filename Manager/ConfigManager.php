<?php

namespace Cyberdean\Security\BotDetectBundle\Manager;


class ConfigManager
{
    /* @var $err4xxCheck bool */
    private $err4xxCheck;

    /* @var $err404Check bool */
    private $err404Check;

    /* @var $uaCheck bool */
    private $uaCheck;

    /* @var $maxBanInterval string */
    private $maxBanInterval;

    /* @var $minBanInterval string */
    private $minBanInterval;

    /* @var $bannedResponseCode int */
    private $bannedResponseCode;

    public function setConfig( $config )
    {
        $this->minBanInterval = $config['min_ban_interval'];
        $this->maxBanInterval = $config['max_ban_interval'];
        $this->bannedResponseCode = $config['ip_banned_response_code'];

        $err404 = $config['err404'];
        $this->err404Check = $err404['check'];

        $err4xx = $config['err4xx'];
        $this->err4xxCheck = $err4xx['check'];

        $ua = $config['ua'];
        $this->uaCheck = $ua['check'];
    }

    /**
     * Get if filter for HTTP 4xx (404 excluded) is enabled
     * @return boolean
     */
    public function isErr4xxCheck()
    {
        return $this->err4xxCheck;
    }

    /**
     * Get if filter for User-Agent is enabled
     * @return boolean
     */
    public function isUaCheck()
    {
        return $this->uaCheck;
    }

    /**
     * Get maximum ban duration
     * @return string
     */
    public function getMaxBanInterval()
    {
        return $this->maxBanInterval;
    }

    /**
     * Get first ban duration
     * @return string
     */
    public function getMinBanInterval()
    {
        return $this->minBanInterval;
    }

    /**
     * Get if filter for HTTP 404 is enabled
     * @return boolean
     */
    public function isErr404Check()
    {
        return $this->err404Check;
    }

    /**
     * Get HTTP response code when ip is banned
     * @return int
     */
    public function getBannedResponseCode()
    {
        return $this->bannedResponseCode;
    }





}