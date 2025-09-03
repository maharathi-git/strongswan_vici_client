
- This is a tool to manage ipsec connections for strongswan charon daemon.
- Built using strongswan vici protocol(vici library).
- While building this has to be linked against strongswan vici library.
 -remember this is made for custom openwrt, and configuration is also custom.

usage:
#ipsecvici [action] [connection]
action: 0 load connection
		1 unload connection
		2 terminate connection
		3 list connection details
connection: ike connection name in ipsec uci config file

