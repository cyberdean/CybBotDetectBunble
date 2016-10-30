<?php

namespace Cyberdean\Security\BotDetectBundle\Entity\Security;

use Doctrine\ORM\Mapping as ORM;

/**
 * Strike
 *
 * @ORM\Table(name="security_strike")
 * @ORM\Entity(repositoryClass="Cyberdean\Security\BotDetectBundle\Repository\Security\StrikeRepository")
 */
class Strike
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
     * @ORM\Column(name="date", type="datetime")
     */
    private $date;

    /**
     * @var string
     *
     * @ORM\Column(name="reason", type="string", length=255, nullable=false)
     */
    private $reason;

    /**
     * @var string
     *
     * @ORM\Column(name="reason_details", type="string", length=255, nullable=true)
     */
    private $reasonDetails;


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
     * @return Strike
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
     * Set date
     *
     * @param \DateTime $date
     *
     * @return Strike
     */
    public function setDate($date)
    {
        $this->date = $date;

        return $this;
    }

    /**
     * Get date
     *
     * @return \DateTime
     */
    public function getDate()
    {
        return $this->date;
    }

    /**
     * Set reason
     *
     * @param string $reason
     *
     * @return Strike
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

    /**
     * @return string
     */
    public function getReasonDetails()
    {
        return $this->reasonDetails;
    }

    /**
     * @param string $reasonDetails
     */
    public function setReasonDetails($reasonDetails)
    {
        $this->reasonDetails = $reasonDetails;
    }


}

