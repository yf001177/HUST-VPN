#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

/* define HOME to be dir for key and cert files... */
#define HOME	"./cert/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"client.crt"
#define KEYF	HOME"client.key"
#define CACERT	HOME"ca.crt"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_SSL(err)	if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }

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

SSL *setupTLSClient(const char *hostname)
{
	// Step 0: OpenSSL library initialization 
	// This step is no longer needed as of version 1.1.0.
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

int setupTCPClient(const char *hostname, int port)
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

	return sockfd;
}

int main(int argc, char *argv[])
{
	char *hostname = "yahoo.com";
	int port = 443;

	if (argc > 1)
		hostname = argv[1];
	if (argc > 2)
		port = atoi(argv[2]);

	/*----------------TLS initialization ----------------*/
	SSL *ssl = setupTLSClient(hostname);

	/*----------------Create a TCP connection ---------------*/
	int sockfd = setupTCPClient(hostname, port);

	/*----------------TLS handshake ---------------------*/
	SSL_set_fd(ssl, sockfd);
	CHK_NULL(ssl);
	int err = SSL_connect(ssl);

	CHK_SSL(err);
	printf("SSL connection is successful\n");
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	/*----------------Send/Receive data --------------------*/
	char buf[9000];
	char sendBuf[200];

	sprintf(sendBuf, "GET / HTTP/1.1\nHost: %s\n\n", hostname);
	SSL_write(ssl, sendBuf, strlen(sendBuf));

	int len;

	do {
		len = SSL_read(ssl, buf, sizeof(buf) - 1);
		buf[len] = '\0';
		printf("%s\n", buf);
	} while (len > 0);
}
