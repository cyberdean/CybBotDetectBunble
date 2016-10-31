<?php

namespace Cyberdean\Security\BotDetectBundle\Command;

use Cyberdean\Security\BotDetectBundle\Entity\Security\BadUrl;
use Cyberdean\Security\BotDetectBundle\Entity\Security\BadUserAgent;
use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class BotDetectAddBaseDataCommand extends ContainerAwareCommand
{
    protected function configure()
    {
        $this
            ->setName('bot-detect:import-basedata')
            ->setDescription('Import into database, set of Suspect/Evil URL & UserAgent')
            //->addOption('option', null, InputOption::VALUE_NONE, 'Option description')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        //if ($input->getOption('option')) {
        //}

        $em = $this->getContainer()->get('doctrine.orm.entity_manager');

        $urlArray = $this->readFile('@CybBotDetectBundle/Resources/dictionnary/url.json');
        foreach ($urlArray as $u) {
            $url = new BadUrl();
            $url->setUrl($u);
            $em->persist($url);
        }
        $em->flush();

        $strictMode = true;//todo option  //Add also web copiers, ...
        $uaCatArray = $this->readFile('@CybBotDetectBundle/Resources/dictionnary/ua.json');
        foreach ($uaCatArray as $cat) {
            if ($strictMode || !$strictMode && !$cat['acceptable']) {
                foreach ($cat['list'] as $u) {
                    $ua = new BadUserAgent();
                    $ua->setUa($u);
                    $em->persist($ua);
                }
            }
        }

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
