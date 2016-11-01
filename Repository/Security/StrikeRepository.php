<?php

namespace Cyberdean\Security\BotDetectBundle\Repository\Security;
use Cyberdean\Security\BotDetectBundle\ReasonEnum;

/**
 * StrikeRepository
 */
class StrikeRepository extends \Doctrine\ORM\EntityRepository
{
    /**
     * Get strikes for user since date to now
     * @param $ip string
     * @param $date \DateTime
     * @return array
     */
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

    /**
     * Suggest url maybe be blacklisted, based on 404 strikes (404 check must be enabled, otherwise there are no data)
     * @return array
     */
    public function getNotBlacklisted404Url() {
        $qb = $this->createQueryBuilder('s')
            ->select('s.id')
            ->from('CybBotDetectBundle:Security\BadUrl', 'url')
            ->where('s.reason = :reason')
            ->andWhere('s.reasonDetails = url.url')
            ->setParameters(array('reason' => ReasonEnum::ERR404));
        $arrayIds = $qb->getQuery()->getArrayResult();
        $excludeIds = array();
        foreach ($arrayIds as $id) {
            $excludeIds[] = $id['id'];
        }

        $qb = $this->createQueryBuilder('s')
            ->select('DISTINCT s.reasonDetails')
            ->where('s.reason = :reason')
            ->andWhere($qb->expr()->notIn('s.id', $excludeIds))
            ->setParameters(array('reason' => ReasonEnum::ERR404));
        return $qb->getQuery()->getArrayResult();
    }

}
