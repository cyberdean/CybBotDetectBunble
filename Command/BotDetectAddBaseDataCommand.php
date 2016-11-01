<?php

namespace Cyberdean\Security\BotDetectBundle\Command;

use Cyberdean\Security\BotDetectBundle\Entity\Security\BadUrl;
use Cyberdean\Security\BotDetectBundle\Entity\Security\BadUserAgent;
use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Command used to import base data, to detect evil users/bots
 */
class BotDetectAddBaseDataCommand extends ContainerAwareCommand
{
    protected function configure()
    {
        $this
            ->setName('bot-detect:import-basedata')
            ->setDescription('Import into database, set of Suspect/Evil URL & UserAgent')
            ->addOption('onlyEvil', null, InputOption::VALUE_NONE, 'Import only evil user-agent (not webcopier, ...)')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $em = $this->getContainer()->get('doctrine.orm.entity_manager');
        $badUrlRepo = $em->getRepository('CybBotDetectBundle:Security\BadUrl');
        $badUARepo = $em->getRepository('CybBotDetectBundle:Security\BadUserAgent');

        $cptUrl = 0;
        $urlArray = $this->readFile('@CybBotDetectBundle/Resources/dictionnary/url.json');
        foreach ($urlArray as $u) {
            if (!$badUrlRepo->findOneBy(array('url' => $u))) {
                $url = new BadUrl();
                $url->setUrl($u);
                $em->persist($url);
                $cptUrl++;
            }
        }
        $em->flush();
        $output->writeln('Imported ' . $cptUrl . ' urls (' . (sizeof($urlArray) - $cptUrl) . ' skipped)');

        $strictMode = !$input->getOption('onlyEvil');
        $uaCatArray = $this->readFile('@CybBotDetectBundle/Resources/dictionnary/ua.json');
        $cptUa = 0;
        $cptUaSkip = 0;
        foreach ($uaCatArray as $cat) {
            if ($strictMode || !$strictMode && !$cat['acceptable']) {
                foreach ($cat->list as $u) {
                    if ($badUARepo->findOneBy(array('ua' => $u))) {
                        $cptUaSkip++;
                    }
                    else {
                        $ua = new BadUserAgent();
                        $ua->setUa($u);
                        $em->persist($ua);
                        $cptUa++;
                    }
                }
            }
        }
        $output->writeln('Imported ' . $cptUa . ' User-Agent (' . $cptUaSkip . ' skipped)');

        $em->flush();
        $output->writeln('Command Done.');
    }

    private function readFile($location) {
        $fileLocator = $this->getContainer()->get('file_locator');
        $path = $fileLocator->locate($location);
        $content = file_get_contents($path);
        return json_decode($content);
    }

}
