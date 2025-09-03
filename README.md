# ipsecvici
- This is a tool to manage ipsec connections for strongswan charon daemon.
- Built using strongswan vici protocol(vici library).
- While building, this has to be linked against strongswan vici library.
 -remember this is made for custom openwrt, and configuration is also custom.

usage:
 ipsecvici [action] [connection]
 
 action: 0 load connection
 		1 unload connection 
		2 terminate connection
		3 list connection details
  
 connection: ike connection name in ipsec uci config file

# uptime
- uptime.c is designed to track the uptime of all the configured ike connections.
- this is also built with strongswan vici protocol
- While building, this has to be linked against strongswan vici library.
- uptime registers for ike and child sa updown events
- uptime uses cpu uptime time to track the uptime of ike connections to avoid problems while changing the time/time format/time zones.
- this runs only if charon daemon is alive, and stops on charon daemon termination

usage:
 compile and run this program after running charon daemon and before establishing any ike connections
