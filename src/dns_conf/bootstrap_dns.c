/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "bootstrap_dns.h"
#include "domain_rule.h"
#include "nameserver.h"
#include "server_group.h"
#include "smartdns/lib/conf.h"
#include "smartdns/util.h"

#include <stdio.h>

char dns_conf_exist_bootstrap_dns;

int _config_update_bootstrap_dns_rule(void)
{
	struct dns_servers *server = NULL;
	FILE *fp = NULL;
	char line[MAX_LINE_LEN];
	char key[MAX_KEY_LEN] = {0};
	char value[MAX_LINE_LEN];
	char ns_ip[DNS_MAX_IPLEN];
	int port = PORT_NOT_DEFINED;
	int filed_num = 0;
	int has_domain_server = 0;
	const char *resolv_file = NULL;

	if (dns_conf_exist_bootstrap_dns == 0) {

		for (int i = 0; i < dns_conf.server_num; i++) {
			if (check_is_ipaddr(dns_conf.servers[i].server) != 0) {
				has_domain_server = 1;
				break;
			}
		}

		if (has_domain_server == 0) {
			return 0;
		}

		if (dns_conf.dns_resolv_file[0] == '\0') {
			resolv_file = DNS_RESOLV_FILE;
		} else {
			resolv_file = dns_conf.dns_resolv_file;
		}

		fp = fopen(resolv_file, "r");
		if (fp == NULL) {
			return 0;
		}

		while (fgets(line, MAX_LINE_LEN, fp)) {
			filed_num = sscanf(line, "%63s %1023[^\r\n]s", key, value);
			if (filed_num != 2) {
				continue;
			}

			if (strncmp(key, "nameserver", MAX_KEY_LEN - 1) != 0) {
				continue;
			}

			if (parse_ip(value, ns_ip, &port) != 0) {
				continue;
			}

			if (port == PORT_NOT_DEFINED) {
				port = DEFAULT_DNS_PORT;
			}

			if (dns_conf.server_num >= DNS_MAX_SERVERS) {
				break;
			}

			safe_strncpy(dns_conf.servers[dns_conf.server_num].server, ns_ip, DNS_MAX_IPLEN);
			dns_conf.servers[dns_conf.server_num].port = port;
			dns_conf.servers[dns_conf.server_num].type = DNS_SERVER_UDP;
			dns_conf.servers[dns_conf.server_num].set_mark = -1;
			dns_conf.servers[dns_conf.server_num].server_flag |= SERVER_FLAG_EXCLUDE_DEFAULT;
			_dns_conf_get_group_set("bootstrap-dns", &dns_conf.servers[dns_conf.server_num]);
			dns_conf.server_num++;
			dns_conf.bootstrap_num++;
			dns_conf_exist_bootstrap_dns = 1;
		}
		fclose(fp);

		if (dns_conf_exist_bootstrap_dns == 0) {
			return 0;
		}
	}

	for (int i = 0; i < dns_conf.server_num; i++) {
		server = &dns_conf.servers[i];
		if (check_is_ipaddr(server->server) == 0) {
			continue;
		}

		_conf_domain_rule_nameserver(server->server, "bootstrap-dns");
	}

	return 0;
}
