#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <dirent.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#define FAIL    -1

#define USE_FUNCTIONS 0

void instructionsForPem (void)
{
  printf ("\n");
  printf ("\n");
  printf ("Did you forget to create your mycert.pem file?\n");
  printf ("\n");
  printf ("Run: openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout mycert.pem -out mycert.pem\n");
  printf ("\n");
  printf ("If you haven't, but that's my best guess of what has gone wrong..\n");
  printf ("\n");
  printf ("\n");
}

#if (USE_FUNCTIONS)
SSL_CTX* InitServerCTX (void)
{
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  OpenSSL_add_all_algorithms ();     /* load & register all cryptos, etc. */
  SSL_load_error_strings ();         /* load all error messages */
  method = TLSv1_2_server_method (); /* create new server-method instance */
  ctx = SSL_CTX_new (method);        /* create new context from method */
  if (ctx == NULL)
  {
    ERR_print_errors_fp (stderr);
    abort ();
  }
  return ctx;
}

void LoadCertificates (SSL_CTX* ctx, const char* CertFile, const char* KeyFile)
{
  /* set the local certificate from CertFile */
  if (SSL_CTX_use_certificate_file (ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
  {
    ERR_print_errors_fp (stderr);
    instructionsForPem ();
    abort ();
  }

  /* set the private key from KeyFile (may be the same as CertFile) */
  if (SSL_CTX_use_PrivateKey_file (ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
  {
    ERR_print_errors_fp (stderr);
    instructionsForPem ();
    abort ();
  }

  /* verify private key */
  if (!SSL_CTX_check_private_key (ctx))
  {
    fprintf (stderr, "Private key does not match the public certificate\n");
    abort ();
  }
}

// Create the SSL socket and intialize the socket address structure
int OpenListener (int port)
{
  int sd;
  struct sockaddr_in addr;

  sd = socket (PF_INET, SOCK_STREAM, 0);
  bzero (&addr, sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons (port);
  addr.sin_addr.s_addr = INADDR_ANY;
  if (bind (sd, (struct sockaddr*)&addr, sizeof (addr)) != 0)
  {
    perror ("can't bind port");
    abort ();
  }
  if (listen (sd, 10) != 0)
  {
    perror ("Can't configure listening port");
    abort ();
  }
  return sd;
}

void ShowCerts (SSL* ssl) //? RBW
{
  X509 *cert;
  char *line;

  cert = SSL_get_peer_certificate (ssl); /* Get certificates (if available) */
  if (cert != NULL)
  {
    printf ("Server certificates:\n");
    line = X509_NAME_oneline (X509_get_subject_name (cert), 0, 0);
    printf ("Subject: %s\n", line);
    free (line);
    line = X509_NAME_oneline (X509_get_issuer_name (cert), 0, 0);
    printf ("Issuer: %s\n", line);
    free (line);
    X509_free (cert);
  }
  else
  {
    printf ("No certificates.\n");
  }
}

void Servlet (SSL* ssl) /* Serve the connection -- threadable */
{
  char buf[1024] = {0};

  int sd, bytes;

  // this is my attempt to run HTTPS.. This is sort of the minimal header that seems
  // to work.  \r is absolutely necessary.

 
  if (SSL_accept (ssl) == FAIL)     /* do SSL-protocol accept */
  {
    ERR_print_errors_fp (stderr);
  }
  else
  {
    ShowCerts (ssl);                          /* get any certificates */
    bytes = SSL_read (ssl, buf, sizeof (buf)); /* get request */
    buf[bytes] = '\0';

    printf ("Client msg:\n[%s]\n", buf);

    if (bytes > 0)
    {
       char cwd[256];
    if (getcwd(cwd, sizeof(cwd)) == NULL)
      perror("getcwd() error");
    else
      #printf("current working directory is: %s\n", cwd);
      SSL_write (ssl, cwd, strlen (cwd));
    }
    else
    {
      ERR_print_errors_fp (stderr);
    }

  }
  sd = SSL_get_fd (ssl); /* get socket connection */
  SSL_free (ssl);        /* release SSL state */
  close (sd);            /* close connection */
}
#endif

int main (int argc, char **argv)
{
  SSL_CTX *ctx;
  int server;
  int portnum;
  char pwd[20]="pwd\n";
      char ls[20]="ls\n";

  const char *szPemPublic = "mycert.pem";
  const char *szPemPrivate = "mycert.pem";
#if (! (USE_FUNCTIONS))
  const SSL_METHOD *method;
#endif

  if (argc != 2)
  {
    printf ("Usage: %s <portnum>\n", argv[0]);
    exit (0);
  }

  portnum = atoi (argv[1]);

  if (portnum < 1024)
  {
    if (getuid () != 0)
    {
      printf ("This program must be run as root/sudo user since your port # (%d) is < 1024\n", portnum);
      exit (1);
    }
  }

  SSL_library_init ();               /* Initialize the SSL library */

#if (USE_FUNCTIONS)
  ctx = InitServerCTX ();            /* initialize SSL */
#else
  // InitServerCTX ();
  OpenSSL_add_all_algorithms ();     /* load & register all cryptos, etc. */
  SSL_load_error_strings ();         /* load all error messages */
  method = TLSv1_2_server_method (); /* create new server-method instance */
  ctx = SSL_CTX_new (method);        /* create new context from method */
  if (ctx == NULL)
  {
    ERR_print_errors_fp (stderr);
    abort ();
  }
#endif

#if (USE_FUNCTIONS)
  LoadCertificates (ctx, szPemPublic, szPemPrivate); /* load certs */
#else
  /* set the local certificate from CertFile */
  if (SSL_CTX_use_certificate_file (ctx, szPemPublic, SSL_FILETYPE_PEM) <= 0)
  {
    ERR_print_errors_fp (stderr);
    instructionsForPem ();
    abort ();
  }

  /* set the private key from KeyFile (may be the same as CertFile) */
  if (SSL_CTX_use_PrivateKey_file (ctx, szPemPrivate, SSL_FILETYPE_PEM) <= 0)
  {
    ERR_print_errors_fp (stderr);
    instructionsForPem ();
    abort ();
  }

  /* verify private key */
  if (!SSL_CTX_check_private_key (ctx))
  {
    fprintf (stderr, "Private key does not match the public certificate\n");
    abort ();
  }
#endif

#if (USE_FUNCTIONS)
  server = OpenListener (portnum); /* create server socket */
#else
  struct sockaddr_in addr;

  server = socket (PF_INET, SOCK_STREAM, 0);
  bzero (&addr, sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons (portnum);
  addr.sin_addr.s_addr = INADDR_ANY;
  if (bind (server, (struct sockaddr*)&addr, sizeof (addr)) != 0)
  {
    perror ("can't bind port");
    abort ();
  }
  if (listen (server, 10) != 0)
  {
    perror ("Can't configure listening port");
    abort ();
  }
#endif

  for (;;)
  {
    struct sockaddr_in addr;
    socklen_t len = sizeof (addr);
    SSL *ssl;

#if (! (USE_FUNCTIONS))
    char buf[1024] = {0};
    int sd, bytes;

    // this is my attempt to run HTTPS.. This is sort of the minimal header that seems
    // to work.  \r is absolutely necessary.
    char cwd[256];
    if (getcwd(cwd, sizeof(cwd)) == NULL)
      perror("getcwd() error");
    else
      printf("Server Runninng...\n");
   
#endif
    int client;

    client = accept (server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
    printf ("Connection: %s:%d\n", inet_ntoa (addr.sin_addr), ntohs (addr.sin_port));
    ssl = SSL_new (ctx);           /* get new SSL state with context */
    SSL_set_fd (ssl, client);      /* set connection socket to SSL state */
#if (USE_FUNCTIONS)
    Servlet (ssl);                 /* service connection */
#else
    if (SSL_accept (ssl) == FAIL)  /* do SSL-protocol accept */
    {
      ERR_print_errors_fp (stderr);
    }
    else
    {
      X509 *cert;
      char *line;

      cert = SSL_get_peer_certificate (ssl); /* Get certificates (if available) */
      if (cert != NULL)
      {
        printf ("Server certificates:\n");
        line = X509_NAME_oneline (X509_get_subject_name (cert), 0, 0);
        printf ("Subject: %s\n", line);
        free (line);
        line = X509_NAME_oneline (X509_get_issuer_name (cert), 0, 0);
        printf ("Issuer: %s\n", line);
        free (line);
        X509_free (cert);
      }
      else
      {
       // printf ("No certificates.\n");
      }

      //ShowCerts (ssl);                         /* get any certificates */
      bytes = SSL_read (ssl, buf, sizeof (buf)); /* get request */
      buf[bytes] = '\0';


      printf ("Client msg:\n[%s]\n", buf);
      

      if (bytes > 0)
      {
       
        if(strcmp(buf,pwd)==0)
         { 
 
           printf(cwd);
           printf("\n");
           SSL_write (ssl, cwd, strlen (cwd));
        }
        else if(strcmp(buf,ls)==0)
        {
               struct dirent *files;
               DIR *dir = opendir(".");
               char dirSub[256]="";
               if (dir == NULL){
                    printf("Directory cannot be opened!" );
    
                 }
               while ((files = readdir(dir)) != NULL)
                      { 
                           
                         printf("%s \n", files->d_name);
                         strcat(files->d_name,"\n");
                         strcat(dirSub,files->d_name);
                       }
               SSL_write (ssl, dirSub, strlen (dirSub));
               closedir(dir);
              
                  
        }
      }
     
      else
      {
        ERR_print_errors_fp (stderr);
      }
    }
    sd = SSL_get_fd (ssl); /* get socket connection */
    SSL_free (ssl);        /* release SSL state */
    close (sd);            /* close connection */
#endif
//    break;
  }
  close (server);      /* close server socket */
  ERR_free_strings (); /* free memory from SSL_load_error_strings */
  EVP_cleanup ();      /* free memory from OpenSSL_add_all_algorithms */
  SSL_CTX_free (ctx);  /* release context */

  return 0;
}