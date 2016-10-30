<?php

namespace Cyberdean\Security\BotDetectBundle\Entity\Security;

use Doctrine\ORM\Mapping as ORM;

/**
 * Ban
 *
 * @ORM\Table(name="security_ban")
 * @ORM\Entity(repositoryClass="Cyberdean\Security\BotDetectBundle\Repository\Security\BanRepository")
 */
class Ban
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
     * @ORM\Column(name="ip", type="string", length=50)
     */
    private $ip;

    /**
     * @var \DateTime
     *
     * @ORM\Column(name="startBan", type="datetime")
     */
    private $startBan;

    /**
     * @var \DateTime
     *
     * @ORM\Column(name="endBan", type="datetime")
     */
    private $endBan;

    /**
     * @var string
     *
     * @ORM\Column(name="reason", type="string", length=255, nullable=true)
     */
    private $reason;


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
     * Set ip
     *
     * @param string $ip
     *
     * @return Ban
     */
    public function setIp($ip)
    {
        $this->ip = $ip;

        return $this;
    }

    /**
     * Get ip
     *
     * @return string
     */
    public function getIp()
    {
        return $this->ip;
    }

    /**
     * Set startBan
     *
     * @param \DateTime $startBan
     *
     * @return Ban
     */
    public function setStartBan($startBan)
    {
        $this->startBan = $startBan;

        return $this;
    }

    /**
     * Get startBan
     *
     * @return \DateTime
     */
    public function getStartBan()
    {
        return $this->startBan;
    }

    /**
     * Set endBan
     *
     * @param \DateTime $endBan
     *
     * @return Ban
     */
    public function setEndBan($endBan)
    {
        $this->endBan = $endBan;

        return $this;
    }

    /**
     * Get endBan
     *
     * @return \DateTime
     */
    public function getEndBan()
    {
        return $this->endBan;
    }

    /**
     * Set reason
     *
     * @param string $reason
     *
     * @return Ban
     */
    public function setReason($reason)
    {
        $this->reason = $reason;

        return $this;
    }

    /**
     * Get reason
     *
     * @return string
     */
    public function getReason()
    {
        return $this->reason;
    }
}

