rule URL_With_Hardcoded_IP
{
    meta:
        description = "URL that uses a raw IP address instead of a domain name"
        severity    = "low"
        category    = "network"
        mitre       = "T1071"
    strings:
        $u = /https?:\/\/[0-9]{1,3}(\.[0-9]{1,3}){3}[:\/]/ ascii wide
    condition:
        $u
}

rule Tor_Onion_Address
{
    meta:
        description = "Embedded Tor hidden-service address"
        severity    = "medium"
        category    = "network"
        mitre       = "T1090.003"
    strings:
        $o = /[a-z2-7]{16,56}\.onion/ ascii wide nocase
    condition:
        $o
}

rule Chat_Service_Exfiltration
{
    meta:
        description = "Telegram bot or Discord webhook endpoints often abused for exfiltration"
        severity    = "medium"
        category    = "network"
        mitre       = "T1567"
    strings:
        $t = "api.telegram.org/bot"        ascii wide nocase
        $d = "discord.com/api/webhooks"    ascii wide nocase
        $d2 = "discordapp.com/api/webhooks" ascii wide nocase
    condition:
        any of them
}