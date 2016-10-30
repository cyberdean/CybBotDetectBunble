<?php

namespace Cyberdean\Security\BotDetectBundle\Repository\Security;

/**
 * StrikeRepository
 */
class StrikeRepository extends \Doctrine\ORM\EntityRepository
{
    public function getStrikesSince($ip, $date) {
        $qb = $this->createQueryBuilder('s');
        $q = $qb->select('COUNT(s.reason) as cpt')
            ->addSelect('s.reason')
            ->where('s.ip = :ip')
            ->andWhere('s.date > :dateLimit')
            ->setParameters(array('ip' => $ip, 'dateLimit' => $date))
            ->groupBy('s.reason');

        return $q->getQuery()->getArrayResult();
    }

}
