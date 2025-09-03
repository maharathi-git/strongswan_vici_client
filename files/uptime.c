#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <libvici.h>

#define STATUS_FILE "/var/log/tunnel_status.csv"
#define UCI_CONFIG "/etc/config/ipsec"

typedef struct {
    char name[64];
    int enabled; // 1 for enabled, 0 for disabled
    int established; // 1 for IKE up, 0 for IKE down
    double total_uptime; // In seconds (from /proc/uptime)
    double start_time;   // Uptime at start (seconds)
    double end_time;     // Uptime at end (seconds)
    char local_host[48];  // For IPv6 (39 chars + margin)
    char remote_host[48]; // For IPv6
    char local_ts[1600];  // For 15 IPv6 subnets (15 * 43 + 14 semicolons + margin)
    char remote_ts[1600]; // For 15 IPv6 subnets
} Tunnel;

#define MAX_TUNNELS 15
Tunnel tunnels[MAX_TUNNELS];
int tunnel_count = 0;

double get_uptime()
{
    FILE *fp = fopen("/proc/uptime", "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open /proc/uptime: %s\n", strerror(errno));
        return 0.0;
    }
    double uptime;
    if( fscanf(fp, "%lf", &uptime)!=1) {
        fclose(fp);
        return 0.0;
    }

    fclose(fp);
    return uptime;
}

void format_uptime(double seconds, char *buffer, size_t len)
{
    int days = (int)(seconds / (24 * 3600));
    seconds -= days * 24 * 3600;
    int hours = (int)(seconds / 3600);
    seconds -= hours * 3600;
    int minutes = (int)(seconds / 60);
    seconds -= minutes * 60;
    int secs = (int)seconds;
    snprintf(buffer, len, "%02d:%02d:%02d:%02d", days, hours, minutes, secs);
}

void remove_ts(char *ts, const char *value, size_t ts_size)
{
    char *pos = strstr(ts, value);
    if (!pos) return;
    char *start = pos;
    char *end = pos + strlen(value);
    if (start > ts && *(start - 1) == ';') start--;
    if (*end == ';') end++;
    memmove(start, end, strlen(end) + 1);
}

void load_uci_config()
{
    FILE *fp = fopen(UCI_CONFIG, "r");
    if (!fp) {
        fprintf(stderr, "Warning: Cannot open %s\n", UCI_CONFIG);
        return;
    }

    char line[256];
    int i = 0;
    while (fgets(line, sizeof(line), fp)!=NULL && i < MAX_TUNNELS) {
        if (strstr(line, "config ipsec") != NULL) {
            if(fgets(line, sizeof(line), fp)!=NULL); // Read name
            char name[64];
            if (sscanf(line, " option name '%[^']'", name) == 1 && name[0] != '\0') {
                strncpy(tunnels[i].name, name, sizeof(tunnels[i].name));
                if(fgets(line, sizeof(line), fp)); // Read enabled
                int enabled;
                if (sscanf(line, " option enabled '%d'", &enabled) == 1) {
                    tunnels[i].enabled = enabled;
                } else {
                    tunnels[i].enabled = 0;
                }
                tunnels[i].established = 0;
                tunnels[i].total_uptime = 0;
                tunnels[i].start_time = 0;
                tunnels[i].end_time = 0;
                tunnels[i].local_host[0] = '\0';
                tunnels[i].remote_host[0] = '\0';
                tunnels[i].local_ts[0] = '\0';
                tunnels[i].remote_ts[0] = '\0';
                i++;
            }
        }
    }
    tunnel_count = i;
    fclose(fp);
}

void save_tunnel_status()
{
    FILE *fp = fopen(STATUS_FILE, "w");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s for writing: %s\n", STATUS_FILE, strerror(errno));
        return;
    }
    for (int i = 0; i < tunnel_count; i++) {
        char uptime_str[16];
        format_uptime(tunnels[i].total_uptime, uptime_str, sizeof(uptime_str));
        fprintf(fp, "%s,%d,%d,%s,%.6f,%.6f,%s,%s,%s,%s\n",
                tunnels[i].name, tunnels[i].enabled, tunnels[i].established,
                uptime_str, tunnels[i].start_time, tunnels[i].end_time,
                tunnels[i].local_host, tunnels[i].remote_host,
                tunnels[i].local_ts, tunnels[i].remote_ts);
    }
    fclose(fp);
}

void update_tunnel(char *name, char *key, char *value)
{
    // if (!name || name[0] == '\0') return;

    static char current_state_ike[16] = "";
    static char current_state_child[16] = "";

    for (int i = 0; i < tunnel_count; i++) {
        if (tunnels[i].name[0] == '\0') continue;
        if (strncmp(tunnels[i].name, name, sizeof(tunnels[i].name)) == 0) {
            if (strncmp(key, "state", 6) == 0) {
                strncpy(current_state_ike, value, sizeof(current_state_ike) - 1);
                current_state_ike[sizeof(current_state_ike) - 1] = '\0';
                if (strncmp(value, "ESTABLISHED", 12) == 0) {
                    tunnels[i].start_time = get_uptime();
                    tunnels[i].established = 1;
                } else if (strncmp(value, "DELETING", 9) == 0) {
                    if (tunnels[i].established) {
                        tunnels[i].end_time = get_uptime();
                        tunnels[i].total_uptime += (tunnels[i].end_time - tunnels[i].start_time);
                        tunnels[i].established = 0;
                        tunnels[i].start_time = 0;
                        tunnels[i].end_time = 0;
                        tunnels[i].local_host[0] = '\0';
                        tunnels[i].remote_host[0] = '\0';
                        tunnels[i].local_ts[0] = '\0';
                        tunnels[i].remote_ts[0] = '\0';
                    }
                }
            } else if (strncmp(key, "local-host", 11) == 0) {
                if (strncmp(current_state_ike, "DELETING", 9) != 0 && tunnels[i].established) {
                    strncpy(tunnels[i].local_host, value, sizeof(tunnels[i].local_host));
                }
            } else if (strncmp(key, "remote-host", 12) == 0) {
                if (strncmp(current_state_ike, "DELETING", 9) != 0 && tunnels[i].established) {
                    strncpy(tunnels[i].remote_host, value, sizeof(tunnels[i].remote_host));
                }
            } else if (strncmp(key, "tasks-active", 13) == 0) {
                strncpy(current_state_child, value, sizeof(current_state_child) - 1);
                current_state_child[sizeof(current_state_child) - 1] = '\0';
            } else if (strncmp(key, "local-ts", 9) == 0) {
                if (strncmp(current_state_child, "CHILD_DELETE", 13) == 0) {
                    remove_ts(tunnels[i].local_ts, value, sizeof(tunnels[i].local_ts));
                } else if (tunnels[i].established) {
                    if (tunnels[i].local_ts[0] != '\0') {
                        strncat(tunnels[i].local_ts, ";", sizeof(tunnels[i].local_ts) - strlen(tunnels[i].local_ts) - 1);
                        strncat(tunnels[i].local_ts, value, sizeof(tunnels[i].local_ts) - strlen(tunnels[i].local_ts) - 1);
                    } else {
                        strncpy(tunnels[i].local_ts, value, sizeof(tunnels[i].local_ts));
                    }
                }
            } else if (strncmp(key, "remote-ts", 10) == 0) {
                if (strncmp(current_state_child, "CHILD_DELETE", 13) == 0) {
                    remove_ts(tunnels[i].remote_ts, value, sizeof(tunnels[i].remote_ts));
                } else if (tunnels[i].established) {
                    if (tunnels[i].remote_ts[0] != '\0') {
                        strncat(tunnels[i].remote_ts, ";", sizeof(tunnels[i].remote_ts) - strlen(tunnels[i].remote_ts) - 1);
                        strncat(tunnels[i].remote_ts, value, sizeof(tunnels[i].remote_ts) - strlen(tunnels[i].remote_ts) - 1);
                    } else {
                        strncpy(tunnels[i].remote_ts, value, sizeof(tunnels[i].remote_ts));
                    }
                }
            }
            save_tunnel_status();
            return;
        }
    }

    if (tunnel_count < MAX_TUNNELS) {
        strncpy(tunnels[tunnel_count].name, name, sizeof(tunnels[tunnel_count].name));
        tunnels[tunnel_count].enabled = 0; // Default
        tunnels[tunnel_count].established = 0;
        tunnels[tunnel_count].total_uptime = 0;
        tunnels[tunnel_count].start_time = 0;
        tunnels[tunnel_count].end_time = 0;
        tunnels[tunnel_count].local_host[0] = '\0';
        tunnels[tunnel_count].remote_host[0] = '\0';
        tunnels[tunnel_count].local_ts[0] = '\0';
        tunnels[tunnel_count].remote_ts[0] = '\0';
        if (strncmp(key, "state", 6) == 0) {
            strncpy(current_state_ike, value, sizeof(current_state_ike) - 1);
            current_state_ike[sizeof(current_state_ike) - 1] = '\0';
            if (strncmp(value, "ESTABLISHED", 12) == 0) {
                tunnels[tunnel_count].start_time = get_uptime();
                tunnels[tunnel_count].established = 1;
            } else if (strncmp(value, "DELETING", 9) == 0) {
                if (tunnels[tunnel_count].established) {
                    tunnels[tunnel_count].end_time = get_uptime();
                    tunnels[tunnel_count].total_uptime += (tunnels[tunnel_count].end_time - tunnels[tunnel_count].start_time);
                    tunnels[tunnel_count].established = 0;
                    tunnels[tunnel_count].start_time = 0;
                    tunnels[tunnel_count].end_time = 0;
                    tunnels[tunnel_count].local_host[0] = '\0';
                    tunnels[tunnel_count].remote_host[0] = '\0';
                    tunnels[tunnel_count].local_ts[0] = '\0';
                    tunnels[tunnel_count].remote_ts[0] = '\0';
                }
            }
        } else if (strncmp(key, "local-host", 11) == 0) {
            if (strncmp(current_state_ike, "DELETING", 9) != 0 && tunnels[tunnel_count].established) {
                strncpy(tunnels[tunnel_count].local_host, value, sizeof(tunnels[tunnel_count].local_host));
            }
        } else if (strncmp(key, "remote-host", 12) == 0) {
            if (strncmp(current_state_ike, "DELETING", 9) != 0 && tunnels[tunnel_count].established) {
                strncpy(tunnels[tunnel_count].remote_host, value, sizeof(tunnels[tunnel_count].remote_host));
            }
        } else if (strncmp(key, "tasks-active", 13) == 0) {
            strncpy(current_state_child, value, sizeof(current_state_child) - 1);
            current_state_child[sizeof(current_state_child) - 1] = '\0';
        } else if (strncmp(key, "local-ts", 9) == 0) {
            if (strncmp(current_state_child, "CHILD_DELETE", 13) == 0) {
                remove_ts(tunnels[tunnel_count].local_ts, value, sizeof(tunnels[tunnel_count].local_ts));
            } else if (tunnels[tunnel_count].established) {
                strncpy(tunnels[tunnel_count].local_ts, value, sizeof(tunnels[tunnel_count].local_ts));
            }
        } else if (strncmp(key, "remote-ts", 10) == 0) {
            if (strncmp(current_state_child, "CHILD_DELETE", 13) == 0) {
                remove_ts(tunnels[tunnel_count].remote_ts, value, sizeof(tunnels[tunnel_count].remote_ts));
            } else if (tunnels[tunnel_count].established) {
                strncpy(tunnels[tunnel_count].remote_ts, value, sizeof(tunnels[tunnel_count].remote_ts));
            }
        }
        tunnel_count++;
        save_tunnel_status();
    }
}

void wait_sigint() {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigprocmask(SIG_BLOCK, &set, NULL);
    while (sigwaitinfo(&set, NULL) == -1 && errno == EINTR) {
        /* wait for signal */
    }
}

void send_sigint() {
    kill(0, SIGINT);
}

static int sa_values(void *user, vici_res_t *res, char *name, void *value, int len)
{
    char *tunnel_name = (char *)user;
    char buff[len + 1];
    strncpy(buff, (char *)value, len + 1);
    buff[len] = 0;
    // fprintf(stderr, "sa_values: tunnel_name=%s, name=%s, val=%s\n", tunnel_name ? tunnel_name : "NULL", name, buff);
    update_tunnel(tunnel_name, name, buff);
    return 0;
}

static int sa_list(void *user, vici_res_t *res, char *name, void *value, int len)
{
    char *tunnel_name = (char *)user;
    char buff[len + 1];
    strncpy(buff, (char *)value, len + 1);
    buff[len] = 0;
    // fprintf(stderr, "sa_list: tunnel_name=%s, name=%s, val=%s\n", tunnel_name ? tunnel_name : "NULL", name, buff);
    update_tunnel(tunnel_name, name, buff);
    return 0;
}

static int child_sas(void *user, vici_res_t *res, char *name)
{
    // fprintf(stderr, "child=%s\n", name);
    return vici_parse_cb(res, NULL, NULL, sa_list, user);
}

static int ike_sa(void *user, vici_res_t *res, char *name)
{
    return vici_parse_cb(res, child_sas, NULL, sa_list, user);
}

static int ike_sas(void *user, vici_res_t *res, char *name)
{
    if (*(int *)user) {
        return vici_parse_cb(res, NULL, sa_values, NULL, name);
    } else {
        return vici_parse_cb(res, ike_sa, NULL, sa_list, name);
    }
    return 0;
}

static void list_cb(void *user, char *name, vici_res_t *res)
{
    int f = 1;
    if (vici_parse_cb(res, ike_sas, NULL, NULL, &f)) {
        fprintf(stderr, "Error: parsing SA event failed: %s\n", strerror(errno));
    }
}

static void list_child(void *user, char *name, vici_res_t *res)
{
    int f = 0;
    if (vici_parse_cb(res, ike_sas, NULL, sa_list, &f)) {
        fprintf(stderr, "Error: parsing SA event failed: %s\n", strerror(errno));
    }
    if (vici_parse_cb(res, ike_sa, NULL, NULL, &f)) {
        fprintf(stderr, "Error: parsing SA event failed: %s\n", strerror(errno));
    }
}

void close_cb(void *ret)
{
    fprintf(stderr, "connection closed\n");
    *(int *)ret = ECONNRESET;
    save_tunnel_status();
    send_sigint();
}

static int monitor_sas(vici_conn_t *conn)
{
    int ret = 0;
    vici_on_close(conn, close_cb, &ret);
    if (vici_register(conn, "ike-updown", list_cb, NULL) != 0) {
        fprintf(stderr, "registering for IKE_SAs failed: %s\n", strerror(errno));
        return errno;
    }
    if (vici_register(conn, "child-updown", list_child, NULL) != 0) {
        fprintf(stderr, "registering for CHILD_SAs failed: %s\n", strerror(errno));
        return errno;
    }
    wait_sigint();
    if (!ret) {
        fprintf(stderr, "disconnecting...\n");
    }
    return ret;
}

void daemonize()
{
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "Fork failed: %s\n", strerror(errno));
        exit(1);
    }
    if (pid > 0) {
        exit(0);
    }
    umask(0);
    if (setsid() < 0) {
        fprintf(stderr, "setsid failed: %s\n", strerror(errno));
        exit(1);
    }
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    open("/dev/null", O_RDWR);
    if(dup(0));
    if(dup(0));
}

int main()
{
    daemonize();
    load_uci_config();
    vici_init();
    vici_conn_t *conn = vici_connect(NULL);
    if (conn) {
        monitor_sas(conn);
        vici_disconnect(conn);
    } else {
        fprintf(stderr, "Failed to connect to charon: %s\n", strerror(errno));
    }
    vici_deinit();
    save_tunnel_status();
    return 0;
}