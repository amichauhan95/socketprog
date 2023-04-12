#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define LOCAL_ABORT()                              \
do                                                 \
{                                                  \
  printf ("Abort at %s:%d\n", __FILE__, __LINE__); \
  abort ();                                        \
} while (0)

#define USE_FUNCTIONS 0

#if (USE_FUNCTIONS)
int OpenConnection (const char *hostname, uint16_t port)
{
  int sd;
  struct hostent *host;
  struct sockaddr_in addr;
  
  if ((host = gethostbyname (hostname)) == NULL)
  {
    perror (hostname);
    LOCAL_ABORT ();
  }
  sd = socket (PF_INET, SOCK_STREAM, 0);
  bzero (&addr, sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons (port);
  addr.sin_addr.s_addr = * (long*) (host->h_addr);

  if (connect (sd, (struct sockaddr*)&addr, sizeof (addr)) != 0)
  {
    close (sd);
    perror (hostname);
    fprintf (stderr, "Is the server running, and on the correct port (%d)?\n", port);
    LOCAL_ABORT ();
  }
  return sd;
}

SSL_CTX* InitCTX (void)
{
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  OpenSSL_add_all_algorithms ();     /* Load cryptos, et.al. */
  SSL_load_error_strings ();         /* Bring in and register error messages */
  method = TLSv1_2_client_method (); /* Create new client-method instance */
  ctx = SSL_CTX_new (method);        /* Create new context */
  if (ctx == NULL)
  {
    ERR_print_errors_fp (stderr);
    LOCAL_ABORT ();
  }
  return ctx;
}

void ShowCerts (SSL* ssl)
{
  X509 *cert;
  char *line;
  cert = SSL_get_peer_certificate (ssl); /* get the server's certificate */
  if (cert != NULL)
  {
    printf ("Server certificates:\n");
    line = X509_NAME_oneline (X509_get_subject_name (cert), 0, 0);
    printf ("Subject: %s\n", line);
    free (line);       /* free the malloc'ed string */
    line = X509_NAME_oneline (X509_get_issuer_name (cert), 0, 0);
    printf ("Issuer: %s\n\n", line);
    free (line);       /* free the malloc'ed string */
    X509_free (cert);  /* free the malloc'ed certificate copy */
  }
  else
  {
    printf ("Info: No client certificates configured.\n");
  }
}
#endif

int main (int argc, char **argv)
{
char input[20] ;
char exitser[20]="exit\n";
char pwd[20]="pwd\n";
char ls[20]="ls\n";
  SSL_CTX *ctx;
  int server;
  SSL *ssl;
  static char buf[1024*1024];
  int bytes;
  char *hostname;
  uint16_t portnum;
#if (!(USE_FUNCTIONS))
  struct hostent *host;
  struct sockaddr_in addr;
  const SSL_METHOD *method;
#endif

 while (strcmp(exitser, input)) 
 {
   printf("ssh>");
   fgets(input, sizeof(input), stdin);
 
  if (argc != 3)
  {
    printf ("usage: %s <hostname> <portnum>\n", argv[0]);
    exit (0);
  }

  // Initialize the SSL library
  SSL_library_init ();

  hostname = argv[1];
  portnum = atoi (argv[2]);

#if (USE_FUNCTIONS)
  ctx = InitCTX ();
  server = OpenConnection (hostname, portnum);
#else
  OpenSSL_add_all_algorithms ();     /* Load cryptos, et.al. */
  SSL_load_error_strings ();         /* Bring in and register error messages */
  method = TLSv1_2_client_method (); /* Create new client-method instance */
  ctx = SSL_CTX_new (method);        /* Create new context */
  if (ctx == NULL)
  {
    ERR_print_errors_fp (stderr);
    LOCAL_ABORT ();
  }

  if ((host = gethostbyname (hostname)) == NULL)
  {
    perror (hostname);
    LOCAL_ABORT ();
  }
  server = socket (PF_INET, SOCK_STREAM, 0);
  bzero (&addr, sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons (portnum);
  addr.sin_addr.s_addr = * (long*) (host->h_addr);

  if (connect (server, (struct sockaddr*)&addr, sizeof (addr)) != 0)
  {
    close (server);
    perror (hostname);
    fprintf (stderr, "Is the server running, and on the correct port (%d)?\n", portnum);
    LOCAL_ABORT ();
  }
#endif

  ssl = SSL_new (ctx);      /* create new SSL connection state */
  SSL_set_fd (ssl, server);    /* attach the socket descriptor */
  if (SSL_connect (ssl) <= 0)   /* perform the connection */
  {
    ERR_print_errors_fp (stderr);
  }
  else
  {
  #if (!(USE_FUNCTIONS))
    X509 *cert;
    char *line;
#endif
    char szRequest[4096];


    sprintf (szRequest, 
             input, hostname, portnum);

    //printf ("Sending:\n %s", szRequest);

    //printf ("\n\nConnected with %s encryption\n", SSL_get_cipher (ssl));

//#if (USE_FUNCTIONS)
//    ShowCerts (ssl);        /* get any certs */
//#else
//    cert = SSL_get_peer_certificate (ssl); /* get the server's certificate */
//    if (cert != NULL)
//    {
//      printf ("Server certificates:\n");
//      line = X509_NAME_oneline (X509_get_subject_name (cert), 0, 0);
//      printf ("Subject: %s\n", line);
//      free (line);       /* free the malloc'ed string */
//      line = X509_NAME_oneline (X509_get_issuer_name (cert), 0, 0);
//      printf ("Issuer: %s\n\n", line);
//      free (line);       /* free the malloc'ed string */
//      X509_free (cert);  /* free the malloc'ed certificate copy */
//    }
//    else
//    {
//      printf ("Info: No client certificates configured.\n");
//    }
//#endif

    SSL_write (ssl, szRequest, strlen (szRequest));   /* encrypt & send message */
    bytes = SSL_read (ssl, buf, sizeof (buf)); /* get reply & decrypt */
    buf[bytes] = 0;
    printf (buf);
    printf ("\n");
    SSL_free (ssl); 

    /* release connection state */
  }
  
 
  close (server);          /* close socket */
  SSL_CTX_free (ctx);      /* release context */
}
  return 0;
}
