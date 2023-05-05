ddns-server
=======

Dynamic DNS with FritzBox and Cloudflare

Easy solution to set up a **local** Dynamic DNS Server if you are running a Fritzbox and using Cloudflare.

### How to

Copy the `docker-compose.yaml` to your server, change the variables and start.

To enable DynDNS in your FritzBox
 - make sure that your server has a static internal IP Address
 - find the DynDNS Settings page
 - check the use DynDNS box
 - enter in Update-URL: `IP:PORT?ip4=<ipaddr>&ip6=<ip6addr>`
  Obviously replace IP and Port with your values
 - domainname, username and password don't matter.
