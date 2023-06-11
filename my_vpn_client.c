#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

/* define HOME to be dir for key and cert files... */
#define HOME	"./cert/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"client.crt"
#define KEYF	HOME"client.key"
#define CACERT	HOME"ca.crt"

#define BUF_SIZE 2000
#define PORT_NUMBER 4433
#define SERVER_IP "127.0.0.1"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_SSL(err)	if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }

#define stderr stdout

struct sockaddr_in peerAddr;

pthread_mutex_t mutex;

int verify_callback(int preverify_ok, X509_STORE_CTX * x509_ctx)
{
	char buf[300];

	X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);

	X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
	printf("subject= %s\n", buf);

	if (preverify_ok == 1) {
		printf("Verification passed.\n");
	} else {
		int err = X509_STORE_CTX_get_error(x509_ctx);

		if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
			printf("Ignore verification result: %s.\n", X509_verify_cert_error_string(err));
			return 1;
		}

		printf("Verification failed: %s.\n", X509_verify_cert_error_string(err));
	}
	return preverify_ok;
}

SSL *Setup_TLS_client(const char *hostname)
{
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;

	meth = SSLv23_client_method();
	ctx = SSL_CTX_new(meth);

#if 1
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
#else
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
#endif
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-2);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-3);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		printf("Private key does not match the certificate public keyn");
		exit(-4);
	}
	ssl = SSL_new(ctx);

	X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);

	X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

	return ssl;
}

int Setup_TCP_client(const char *hostname, int port)
{
	struct sockaddr_in server_addr;

	// Get the IP address from hostname
	struct hostent *hp = gethostbyname(hostname);

	// Create a TCP socket
	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// Fill in the destination information (IP, port #, and family)
	memset(&server_addr, '\0', sizeof(server_addr));
	memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
	//server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14"); 
	server_addr.sin_port = htons(port);
	server_addr.sin_family = AF_INET;

	// Connect to the destination
	connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr));
    printf("TCP connect succeed:%s:%d\n",inet_ntoa(server_addr.sin_addr),port);
	return sockfd;
}

int Verify(SSL * ssl){
    char username[20];
    char passwd[20];
    char buf[BUF_SIZE];
    int len = SSL_read(ssl,buf,BUF_SIZE);   
    //username
    printf("%s\n",buf);
    scanf("%s",username);
    getchar();
    SSL_write(ssl,username,strlen(username)+1);
    //passwd
    SSL_read(ssl,buf,BUF_SIZE);
    //check
    if(strcmp(buf,"Please input password: ")){
        printf("No such user\n");
        return -1;
    }
    printf("%s\n",buf);
    scanf("%s",passwd);
    getchar();
    SSL_write(ssl,passwd,strlen(passwd)+1);
    //check
    SSL_read(ssl,buf,BUF_SIZE);
    if(strcmp(buf,"Verify succeed\n")){
        printf("Wrong password!\n");
        return -2;
    }
    printf("Verify succeed!\n");
    return 1;
}

int Get_virtual_ip(SSL * ssl){
    int virtual_ip;
    char buf[BUF_SIZE];
    SSL_read(ssl,buf,sizeof(buf));
    virtual_ip=atoi(buf);
    printf("receive virtual IP: 192.168.53.%d/24\n",virtual_ip);
    return virtual_ip;
}


int Create_tun_device(SSL *ssl,int virtual_ip){
    struct ifreq ifr;
    memset(&ifr,0,sizeof(ifr));
    ifr.ifr_flags=IFF_TUN|IFF_NO_PI;
    //IFF_TUN:create a tun device
    //IFF_NO_PI:Do not provide packet information

    pthread_mutex_lock(&mutex);
    int tunfd = open("/dev/net/tun", O_RDWR);
    pthread_mutex_unlock(&mutex);
    
    if (tunfd == -1) {
		fprintf(stderr,"Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}
	int ret = ioctl(tunfd, TUNSETIFF, &ifr);
	if (ret == -1) {
		fprintf(stderr,"Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}

    //tun id
    int tunId = atoi(ifr.ifr_name+3);
    if(tunId == 127) {
        fprintf(stderr,"Error! There are more than 127 clients!\n");
        return -1;
    }

    //client_virtual_ip=tunID+127,target_virtual_ip=tunID+1
    char cmd[60];
    //add new device
    sprintf(cmd,"sudo ifconfig tun%d 192.168.53.%d/24 up",tunId,virtual_ip);
    system(cmd);
    //route new ip
    sprintf(cmd,"route add -net 192.168.60.0/24 tun%d",tunId); // target -> client route
	system(cmd);

    return tunfd;
}

int main(int argc, char *argv[]){
    char *hostname="yangfan.com";
    int port=PORT_NUMBER;
    if (argc > 1)
		hostname = argv[1];
	if (argc > 2)
		port = atoi(argv[2]);

    SSL *ssl = Setup_TLS_client(hostname);
    printf("SSL init finish\n");
    int sockfd = Setup_TCP_client(hostname, port);
    printf("TCP finish\n");

    SSL_set_fd(ssl,sockfd);
    CHK_NULL(ssl);
    int err=SSL_connect(ssl);
    CHK_SSL(err);
    printf("SSL connection is successful\n");
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    //to verify user and passwd
    if(Verify(ssl)!=1){
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return 0;
    }

    int virtual_ip=Get_virtual_ip(ssl);
    int tunfd=Create_tun_device(ssl,virtual_ip);

    int len;
    char buf[BUF_SIZE];
    while (1) {
		fd_set readFDSet;

		FD_ZERO(&readFDSet);
		FD_SET(sockfd, &readFDSet);
		FD_SET(tunfd, &readFDSet);
		select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

		//send
		if (FD_ISSET(tunfd,&readFDSet)){
            memset(buf,0,sizeof(buf));
            len=read(tunfd,buf,BUF_SIZE);
            buf[len++]=0;
            SSL_write(ssl,buf,len);
        }
        //recevied
		if (FD_ISSET(sockfd,&readFDSet)){
            memset(buf,0,sizeof(buf));
            len=SSL_read(ssl,buf,BUF_SIZE);
            if(len==0){
                fprintf(stderr,"the ssl socket close!\n");
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(sockfd);
                return 0;
            }
            buf[len++]=0;
            write(tunfd,buf,len);
        }
	}
}