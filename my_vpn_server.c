#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <shadow.h>
#include <crypt.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <pthread.h>


/* define HOME to be dir for key and cert files... */
#define HOME	"./cert/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"server.crt"
#define KEYF	HOME"server.key"
#define CACERT	HOME"ca.crt"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)	if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)	if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

#define SERVER_PORT 4433
#define BUF_SIZE 2000

#define stderr stdout

struct para{
    SSL_CTX *ctx;
    int client_sock;
};

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

		printf("Verification failed: %s.\n", X509_verify_cert_error_string(err));
	}
	return preverify_ok;
}

SSL_CTX * Server_ssl_init(){
    SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;

    // Step 0: OpenSSL library initialization 
	// This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	// Step 1: SSL context initialization
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);

#if 1
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
#else
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
#endif
	SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

	// Step 2: Set up the server certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(5);
	}

    return ctx;
}

int Setup_TCP_server()
{
	struct sockaddr_in sa_server;
	int listen_sock;

	listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	CHK_ERR(listen_sock, "socket");
	memset(&sa_server, '\0', sizeof(sa_server));
	sa_server.sin_family = AF_INET;
	sa_server.sin_addr.s_addr = INADDR_ANY;
	sa_server.sin_port = htons(SERVER_PORT);
	int err = bind(listen_sock, (struct sockaddr *) &sa_server, sizeof(sa_server));

	CHK_ERR(err, "bind");
	err = listen(listen_sock, 5);
	CHK_ERR(err, "listen");
	return listen_sock;
}

int Accept_TCP_socket(int listen_sock){
    struct sockaddr_in sa_client;
	size_t client_len = sizeof(struct sockaddr_in);
    int sock = accept(listen_sock, (struct sockaddr *) &sa_client, &client_len);
    if (sock == -1) {
		fprintf(stderr, "Accept TCP connect failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}
    printf("Accept TCP connect from %s:%d\n",inet_ntoa(sa_client.sin_addr),sa_client.sin_port);
    return sock;
}

int Verify(SSL *ssl){
    //name
    char username[]="Please input username: ";
    SSL_write(ssl,username,strlen(username)+1);
    char name[BUF_SIZE];
    int name_len=SSL_read(ssl,name,BUF_SIZE);
    struct spwd *pw=getspnam(name);
    if(pw==NULL){
        char n[]="No such user";
        fprintf(stderr,"%s:%s\n",n,name);
        SSL_write(ssl,n,strlen(n)+1);
        return -1;
    }
    
    //password
    char userpasswd[]="Please input password: ";
    SSL_write(ssl,userpasswd,strlen(userpasswd)+1);
    char passwd[BUF_SIZE];
    int passwd_len=SSL_read(ssl,passwd,BUF_SIZE);

    char *epasswd=crypt(passwd,pw->sp_pwdp);
    if(strcmp(epasswd,pw->sp_pwdp)){
        char n[]="Wrong password!";
        fprintf(stderr,"%s\n",n);
        SSL_write(ssl,n,strlen(n)+1);
        return -2;
    }

    char ok[]="Verify succeed\n";
    printf("%s",ok);
    SSL_write(ssl,ok,strlen(ok)+1);
    return 1;
}

int Create_tun_device(SSL *ssl,int *virtual_ip){
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
    sprintf(cmd,"sudo ifconfig tun%d 192.168.53.%d/24 up",tunId,tunId+1);
    system(cmd);
    //route new ip
    sprintf(cmd,"route add -host 192.168.53.%d tun%d",tunId+127,tunId); // target -> client route
	system(cmd);
    system("sudo sysctl net.ipv4.ip_forward=1");

    *virtual_ip = tunId + 127;   //client_virtual_ip
    return tunfd;
}

void Select_tunnel(SSL *ssl,int sockfd,int tunfd){
    char buf[BUF_SIZE];
    int len;
    while(1){
		fd_set readFDSet;
		FD_ZERO(&readFDSet);
		FD_SET(sockfd,&readFDSet);
		FD_SET(tunfd,&readFDSet);
		select(FD_SETSIZE,&readFDSet,NULL,NULL,NULL);

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
                return;
            }
            buf[len++]=0;
            write(tunfd,buf,len);
        }
	}
}

void* New_thread(void *arg){
    struct para tmp=*(struct para *)arg;
    SSL_CTX *ctx=tmp.ctx;
    int client_sock=tmp.client_sock;
    SSL *ssl=SSL_new(ctx);
    SSL_set_fd(ssl,client_sock);
    int err=SSL_accept(ssl);
    if(err<0){
        fprintf(stderr,"Error! ssl_accept return %d\n",err);
        return;
    }
    printf("SSL connection established!\n");

    //Verify the user and password
    if(Verify(ssl)!=1){
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_sock);
        fprintf(stderr,"Error! Verify failed\n");
        return;
    }
    
    //create tun device
    int virtual_ip;
    int tunfd=Create_tun_device(ssl,&virtual_ip);
    if(tunfd==-1){
		fprintf(stderr,"error! create tun_device failed!\n");
		return;
	}
    char buf[10];
    sprintf(buf,"%d",virtual_ip);
    printf("send virtual IP: 192.168.53.%d/24\n",virtual_ip);
    SSL_write(ssl,buf,strlen(buf)+1);

    //Interact
    Select_tunnel(ssl,client_sock,tunfd);

    //die
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_sock);
    return;
}

int main(){
    SSL_CTX *ctx=Server_ssl_init();
    printf("SSL init finish\n");
    int listen_sock=Setup_TCP_server();
    printf("Listen socket finish\n");

    while(1){
        int client_sock=Accept_TCP_socket(listen_sock);
        if(client_sock==-1){
		   fprintf(stderr,"Error! client_sock return -1!\n");
		   continue;
	   	}
        struct para client_arg;
        client_arg.client_sock=client_sock;
        client_arg.ctx=ctx;

        pthread_t tid;
        int ret=pthread_create(&tid,NULL,New_thread,(void *)&client_arg);
        if(ret!=0){
            fprintf(stderr,"Error! pthread_create return %d\n",ret);
            return -1;
        }
    }

    close(listen_sock);
    SSL_CTX_free(ctx);
    return 0;
}