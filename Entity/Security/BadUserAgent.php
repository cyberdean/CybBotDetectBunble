<?php

namespace Cyberdean\Security\BotDetectBundle\Entity\Security;

use Doctrine\ORM\Mapping as ORM;

/**
 * BadUserAgent
 *
 * @ORM\Table(name="security_bad_user_agent")
 * @ORM\Entity(repositoryClass="Cyberdean\Security\BotDetectBundle\Repository\Security\BadUserAgentRepository")
 */
class BadUserAgent
{
    /**
     * @var int
     *
     * @ORM\Column(name="id", type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private $id;

    /**
     * @var string
     *
     * @ORM\Column(name="ua", type="string", length=255, unique=true)
     */
    private $ua;


    /**
     * Get id
     *
     * @return int
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Set ua
     *
     * @param string $ua
     *
     * @return BadUserAgent
     */
    public function setUa($ua)
    {
        $this->ua = $ua;

        return $this;
    }

    /**
     * Get ua
     *
     * @return string
     */
    public function getUa()
    {
        return $this->ua;
    }
}

