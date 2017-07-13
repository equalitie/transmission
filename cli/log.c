#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>


typedef enum tr_address_type
{
    TR_AF_INET,
    TR_AF_INET6,
    NUM_TR_AF_INET_TYPES
}
tr_address_type;

typedef struct tr_address
{
    tr_address_type type;
    union
    {
        /* The order here is important for tr_in{,6}addr_any initialization,
         * since we can't use C99 designated initializers */
        struct in6_addr addr6;
        struct in_addr addr4;
    } addr;
} tr_address;



void log_init(void);
void log_exit(void);

void log_update_own_address(const struct sockaddr *sa, int sa_len);

void log_dht_set_my_id(const unsigned char *myid);
void log_dht_routing_displace(const unsigned char *id, const struct sockaddr *sa, int sa_len);
void log_dht_routing_add(const unsigned char *id, const struct sockaddr *sa, int sa_len);
void log_dht_rpc_request(const unsigned char *id, const struct sockaddr *sa, int sa_len, const char *type);
void log_dht_rpc_reply(const unsigned char *id, const struct sockaddr *sa, int sa_len, const char *type);

void log_connection_start(tr_address peer_address, int port, int is_ledbat, int is_incoming);
void log_connection_end(tr_address peer_address, int port, uint64_t bytes_sent, uint64_t bytes_received, int is_encrypted, int is_error);


static void render_sockaddr(const struct sockaddr *sa, int sa_len, char *ip_buffer, int *port)
{
	(void)(sa_len);
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in*)sa;
		*port = ntohs(sin->sin_port);
		char intbuffer[8];
		ip_buffer[0] = 0;
		for (int i = 0; i < 4; i++) {
			sprintf(intbuffer, "%d", (ntohl(sin->sin_addr.s_addr) >> (24 - (i * 8))) & 0xff);
			if (i != 0) {
				strcat(ip_buffer, ".");
			}
			strcat(ip_buffer, intbuffer);
		}
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin = (struct sockaddr_in6*)sa;
		*port = ntohs(sin->sin6_port);
		char intbuffer[8];
		ip_buffer[0] = 0;
		for (int i = 0; i < 8; i++) {
			sprintf(intbuffer, "%x", sin->sin6_addr.s6_addr[2 * i] << 8 | sin->sin6_addr.s6_addr[2 * i + 1]);
			if (i != 0) {
				strcat(ip_buffer, ":");
			}
			strcat(ip_buffer, intbuffer);
		}
	} else {
		ip_buffer[0] = 0;
		*port = -1;
	}
}

static void render_tr_address(tr_address address, char *ip_buffer)
{
	if (address.type == TR_AF_INET) {
		char intbuffer[8];
		ip_buffer[0] = 0;
		for (int i = 0; i < 4; i++) {
			sprintf(intbuffer, "%d", (ntohl(address.addr.addr4.s_addr) >> (24 - (i * 8))) & 0xff);
			if (i != 0) {
				strcat(ip_buffer, ".");
			}
			strcat(ip_buffer, intbuffer);
		}
	} else if (address.type == TR_AF_INET6) {
		char intbuffer[8];
		ip_buffer[0] = 0;
		for (int i = 0; i < 8; i++) {
			sprintf(intbuffer, "%x", address.addr.addr6.s6_addr[2 * i] << 8 | address.addr.addr6.s6_addr[2 * i + 1]);
			if (i != 0) {
				strcat(ip_buffer, ":");
			}
			strcat(ip_buffer, intbuffer);
		}
	} else {
		ip_buffer[0] = 0;
	}
}

static void render_id(const unsigned char *id, char *buffer)
{
	buffer[0] = 0;
	for (int i = 0; i < 20; i++) {
		char byte[8];
		sprintf(byte, "%02x", id[i]);
		strcat(buffer, byte);
	}
}



static FILE* logfile = NULL;
static int logfirst = 1;

void log_init(void)
{
	logfile = fopen("transmission-instrumentation.log.json", "w");
	fprintf(logfile, "[\n");
	logfirst = 1;
}

void log_exit(void)
{
	fprintf(logfile, "]\n");
	fclose(logfile);
}

static void log_entry(const char *json_entry)
{
	if (logfirst) {
		logfirst = 0;
	} else {
		fprintf(logfile, ", ");
	}
	fprintf(logfile, "%s\n", json_entry);
	fflush(logfile);
}

void log_update_own_address(const struct sockaddr *sa, int sa_len)
{
	(void)(sa);
	(void)(sa_len);

}

void log_dht_set_my_id(const unsigned char *myid)
{
	struct timeval time;
	gettimeofday(&time, NULL);
	
	char myid_buffer[64];
	render_id(myid, myid_buffer);
	
	char entry[4096];
	sprintf(entry,
		"{"
			"\"type\": \"dht-own-id\","
			"\"timestamp\": %ld.%06ld,"
			"\"my-id\": \"%s\""
		"}"
		, time.tv_sec, time.tv_usec, myid_buffer);
	
	log_entry(entry);
}

void log_dht_routing_displace(const unsigned char *id, const struct sockaddr *sa, int sa_len)
{
	struct timeval time;
	gettimeofday(&time, NULL);
	
	int port;
	char address[256];
	render_sockaddr(sa, sa_len, address, &port);
	
	char id_buffer[64];
	render_id(id, id_buffer);
	
	char entry[4096];
	sprintf(entry,
		"{"
			"\"type\": \"dht-displace-node\","
			"\"timestamp\": %ld.%06ld,"
			"\"peer-id\": \"%s\","
			"\"peer-address\": \"%s\","
			"\"peer-port\": %d"
		"}"
		, time.tv_sec, time.tv_usec, id_buffer, address, port);
	log_entry(entry);
}

void log_dht_routing_add(const unsigned char *id, const struct sockaddr *sa, int sa_len)
{
	struct timeval time;
	gettimeofday(&time, NULL);
	
	int port;
	char address[256];
	render_sockaddr(sa, sa_len, address, &port);
	
	char id_buffer[64];
	render_id(id, id_buffer);
	
	char entry[4096];
	sprintf(entry,
		"{"
			"\"type\": \"dht-add-node\","
			"\"timestamp\": %ld.%06ld,"
			"\"peer-id\": \"%s\","
			"\"peer-address\": \"%s\","
			"\"peer-port\": %d"
		"}"
		, time.tv_sec, time.tv_usec, id_buffer, address, port);
	log_entry(entry);
}

void log_dht_rpc_request(const unsigned char *id, const struct sockaddr *sa, int sa_len, const char *type)
{
	int port;
	char address[256];
	render_sockaddr(sa, sa_len, address, &port);
	
	char id_buffer[64];
	render_id(id, id_buffer);
	
	struct timeval time;
	gettimeofday(&time, NULL);
	
	char entry[4096];
	sprintf(entry,
		"{"
			"\"type\": \"dht-rpc-request\","
			"\"timestamp\": %ld.%06ld,"
			"\"peer-id\": \"%s\","
			"\"peer-address\": \"%s\","
			"\"peer-port\": %d,"
			"\"rpc-type\": \"%s\""
		"}"
		, time.tv_sec, time.tv_usec, id_buffer, address, port, type);
	log_entry(entry);
}

void log_dht_rpc_reply(const unsigned char *id, const struct sockaddr *sa, int sa_len, const char *type)
{
	int port;
	char address[256];
	render_sockaddr(sa, sa_len, address, &port);
	
	char id_buffer[64];
	render_id(id, id_buffer);
	
	struct timeval time;
	gettimeofday(&time, NULL);
	
	char entry[4096];
	sprintf(entry,
		"{"
			"\"type\": \"dht-rpc-reply\","
			"\"timestamp\": %ld.%06ld,"
			"\"peer-id\": \"%s\","
			"\"peer-address\": \"%s\","
			"\"peer-port\": %d,"
			"\"rpc-type\": \"%s\""
		"}"
		, time.tv_sec, time.tv_usec, id_buffer, address, port, type);
	log_entry(entry);
}

void log_connection_start(tr_address peer_address, int port, int is_ledbat, int is_incoming)
{
	char address[256];
	render_tr_address(peer_address, address);
	
	struct timeval time;
	gettimeofday(&time, NULL);
	
	char entry[4096];
	sprintf(entry,
		"{"
			"\"type\": \"connection-start\","
			"\"timestamp\": %ld.%06ld,"
			"\"peer-address\": \"%s\","
			"\"peer-port\": %d,"
			"\"ledbat\": %s,"
			"\"incoming\": %s"
		"}"
		, time.tv_sec, time.tv_usec, address, port, is_ledbat ? "true" : "false", is_incoming ? "true" : "false");
	log_entry(entry);
}

void log_connection_end(tr_address peer_address, int port, uint64_t bytes_sent, uint64_t bytes_received, int is_encrypted, int is_error)
{
	char address[256];
	render_tr_address(peer_address, address);
	
	struct timeval time;
	gettimeofday(&time, NULL);
	
	char entry[4096];
	sprintf(entry,
		"{"
			"\"type\": \"connection-end\","
			"\"timestamp\": %ld.%06ld,"
			"\"peer-address\": \"%s\","
			"\"peer-port\": %d,"
			"\"bytes-sent\": %llu,"
			"\"bytes-received\": %llu,"
			"\"encrypted\": %s,"
			"\"reason-error\": %s"
		"}"
		, time.tv_sec, time.tv_usec, address, port, bytes_sent, bytes_received, is_encrypted ? "true" : "false", is_error ? "true" : "false");
	log_entry(entry);

}

