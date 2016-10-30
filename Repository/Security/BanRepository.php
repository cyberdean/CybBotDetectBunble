<?php

namespace Cyberdean\Security\BotDetectBundle\Repository\Security;
use Cyberdean\Security\BotDetectBundle\Entity\Security\Ban;

/**
 * BanRepository
 *
 * This class was generated by the Doctrine ORM. Add your own custom
 * repository methods below.
 */
class BanRepository extends \Doctrine\ORM\EntityRepository
{
    /**
     * @param $ip
     * @return Ban|null
     */
    public function getCurrentIpBan($ip) {
        $qb = $this->createQueryBuilder('b');
        $q = $qb->where('b.ip = :ip')
            ->andWhere('b.endBan > :end')
            ->setParameters(array('ip' => $ip, 'end' => new \DateTime()));

        return $q->getQuery()->getOneOrNullResult();
    }

}