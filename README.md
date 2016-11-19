# CybBotDetectBundle

This bundle provide more Security, to your application by filter requests made by evil users / bots.

If an attacker try to hack your application (bruteforce, url scans, ...), it is detected and attacker ip address is banned of your application OR of your complete system with Fail2Ban.

## Features :
- Configurable, you can choose to enable / disable checks, set limits, ...
- Extendable : provides events to easily connect your methods (send alert email, ...)
- Fail2Ban Integration

## How it work
There is a strike system, when an users go beyond the limits, a ip address ban is applied.
Strike is separated in different categories (each can be enabled / disabled) :
- UserAgent
- Call non existant suspect URL (like /wp-admin/login)
- Call request which return 404 error
- Call request which return 4xx error (404 excluded)
- Your custom strikes (like login form bruteforce)

Ban time is progressive : it double at each ban of same ip. (min / max configurable)

## Fail2Ban Integration
Which provide more ?

If you don't use Fail2Ban, the HTTP request is received by your Apache/Nginx and processed (even if ip is banned -> return 403)
but if you use Fail2Ban, the HTTP request was blocked on the Firewall directly (iptables), and your web server never receive the malicous requests -> remove useless load

Futhermore by using it, you prevent attacker to try other system ports like SSH, FTP, ...


WIP - coming soon :)

## Installation
[Packagist](https://packagist.org/packages/cyberdean/botdetect-bundle)

Simply run : `composer require cyberdean/botdetect-bundle`
Beta : `composer require cyberdean/botdetect-bundle:@beta`

Add to AppKernel.php : `new Cyberdean\Security\BotDetectBundle\CybBotDetectBundle()`

Don't forget to update your database : `php bin/console doctrine:schema:update --force`

Optional, Import pre-configured Bad User-Agent / Url in database :
`php bin/console bot-detect:import-basedata`

If you don't run this command, don't forget to fill database yourself, otherwise UA & URL check are useless.

## Configuration
config.yml - Default values
``` yml
cyb_bot_detect:
    # Minimum PHP DateInterval ban time
    min_ban_interval: 'P3D'
    # Maximum PHP DateInterval ban time
    max_ban_interval: 'P6M'
    # HTTP code when user ip is banned
    ip_banned_response_code: 403
    err404:
        #If true strike 404 errors
        check: false
    err4xx:
        #If true strike 4xx errors (not 404)
        check: true
    ua:
        #If true strike ua bad bot
        check: true
```


## License

GNU General Public License v3 (GPL-3), see LICENSE file.

Simple explanation : https://tldrlegal.com/license/gnu-general-public-license-v3-(gpl-3)