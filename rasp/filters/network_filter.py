from __future__ import unicode_literals
from future.standard_library import install_aliases
install_aliases()
from urllib.parse import urlparse
from ipaddress import ip_address, ip_network

from builtins import super

from rasp.core.filter import AbstractFilter, FilterResult, FilterContext


class DefaultNetworkFilter(AbstractFilter):
    """Network access filtering.

    Syntax:
        [default.network.whitelist.domain]
        'domain_name'     # www.example.com

        [default.network.whitelist.ip]
        'ip_address'      # e.g. 192.168.0.1
        'subnet'          # e.g. 192.168.0.1/24

        [default.network.blacklist.domain]
        'domain_name'     # www.example.com

        [default.network.blacklist.ip]
        'ip_address'      # e.g. 192.168.0.1
        'subnet'          # e.g. 192.168.0.1/24
    """

    name = 'DefaultNetworkFilter'
    context = FilterContext.URL
    rule_entries = (
        'default.network.whitelist.domain',
        'default.network.whitelist.ip',
        'default.network.blacklist.domain',
        'default.network.blacklist.ip',
    )

    def __init__(self, rule=None):
        super().__init__(rule)

    def is_unix_domain(self, url):
        parsed_url = urlparse(url)
        if parsed_url.scheme == 'unix':
            return True

        return False

    def has_suspicious_scheme(self, url):
        parsed_url = urlparse(url)
        if parsed_url.scheme not in (
            '',
            'http',
            'https',
            'ftp',
            'ftps',
            'ssh2.shell',
            'ssh2.exec',
            'ssh2.tunnel',
            'ssh2.sftp',
            'ssh2.scp',
        ):
            return True

        return False

    def get_unobfuscated_ip(self, netloc):
        ip = None

        try:
            ip = ip_address(netloc)   # 127.0.0.1, 2130706433
            return str(ip)
        except ValueError:
            pass

        try:
            ip = ip_address(int(netloc, 0))   # 0x7f000001
            return str(ip)
        except ValueError:
            pass

        try:
            # 0x7f.0x0.0x0.0x1
            if '.' in netloc:
                if len(netloc.split('.')) == 4:
                    ip = '.'.join([str(int(i, 0)) for i in netloc.split('.')])
                    return str(ip_address(ip))
        except Exception:
            pass

        return ip

    def is_whitelisted_domain(self, netloc):
        if self.rule['default.network.whitelist.domain']:
            return any([d in netloc for d in self.rule['default.network.whitelist.domain']])
        else:
            return False

    def is_whitelisted_ip(self, netloc):
        if self.rule['default.network.whitelist.ip']:
            return any([ip_network(netloc, strict=False) in ip_network(ip, strict=False) for ip in self.rule['default.network.whitelist.ip']])
        else:
            return False

    def is_blacklisted_domain(self, netloc):
        if self.rule['default.network.blacklist.domain']:
            return any([d in netloc for d in self.rule['default.network.blacklist.domain']])
        else:
            return False

    def is_blacklisted_ip(self, netloc):
        if self.rule['default.network.blacklist.ip']:
            return any([ip_network(netloc, strict=False) in ip_network(ip, strict=False) for ip in self.rule['default.network.blacklist.ip']])
        else:
            return False

    def filter(self, message):
        for url in message['normalized_args']:
            if self.is_unix_domain(url):
                return FilterResult.IGNORE

            if self.has_suspicious_scheme(url):
                return FilterResult.ALERT

            host = urlparse(url).netloc
            ip = self.get_unobfuscated_ip(host)

            if ip is not None:
                if self.is_whitelisted_ip(ip):
                    return FilterResult.IGNORE
                if self.is_blacklisted_ip(ip):
                    return FilterResult.ALERT
            else:
                # domain
                if self.is_whitelisted_domain(host):
                    return FilterResult.IGNORE
                if self.is_blacklisted_domain(host):
                    return FilterResult.ALERT

        return FilterResult.DEFAULT
