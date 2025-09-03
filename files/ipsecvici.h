#ifndef IPSECVICI_H
#define IPSECVICI_H

#include <libvici.h>

#define INSTANCE_LEN 40
#define IP_LEN 48
#define MAX_SUBNETS 10
#define MAX_BYPASSNETS 10

/**
 * child sa struct
 */
typedef struct child_sa_t {
    char name[INSTANCE_LEN+16];
    int left;
    int right;
}CHILD_SA_T;

/**
 * ike connection struct
 */
typedef struct ike_conn_t {
    char name[INSTANCE_LEN];
    char local_addrs[IP_LEN];
    char remote_addrs[IP_LEN];
    char local_id[IP_LEN];
    char remote_id[IP_LEN];
    int enabled;
    int ike_version;
    int ike_aggressive;
    char auth[8];
    char psk[INSTANCE_LEN];
    char ike_proposal[INSTANCE_LEN];
    char ike_rekey[8];
    char dpd_delay[8];
    char dpd_timeout[8];
    char tunnel_mode[16];
    char peer_mode[8];
    char esp_proposal[INSTANCE_LEN];
    char esp_rekey[8];
    char dpd_action[8];
    char start_action[8];
    int cnt_l;
    int cnt_r;
    int child_cnt;
    CHILD_SA_T child_sa[MAX_SUBNETS*MAX_SUBNETS];
    int bypass_lan;
    char local_net[MAX_SUBNETS][IP_LEN];
    char remote_net[MAX_SUBNETS][IP_LEN];
    char bypass_net[MAX_BYPASSNETS][IP_LEN];
}IKE_CONN_T;

/**
 * conn info struct
 */
typedef struct {
    char **response;
    size_t *offset;
    size_t *resp_size;
} conn_info_t;

char *charon_connect(int action, const char *ike);

#endif
