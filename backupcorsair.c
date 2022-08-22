/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_get_mod_exp.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: msoler-e <msoler-e@student.42barcel>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/07/13 14:34:39 by msoler-e          #+#    #+#             */
/*   Updated: 2022/08/03 14:13:37 by msoler-e         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */
#include "corsair.h"

int desxifratge(t_rsa *crt_rsa,int k, RSA *key)
{
	int fd;
	char buffer;
	int	n;
	char	*file;
	unsigned char *missatge;
	unsigned char *missatgedecript;
	int	z;
	int longitud;
	int x;
	int	len;
	char	c;

 	
	file = malloc(sizeof(char)*(ft_strlen(crt_rsa[k].nom) + 1));
 	
	z = 0;
    while (z < strlen(crt_rsa[k].nom) - 3)
    {
        file[z] = crt_rsa[k].nom[z];
        z++;
    }
    file[z++] = 'b';
    file[z++] = 'i';
    file[z++] = 'n';
    file[z] = '\0';	
	len = 0;
    fd = open(file, O_RDONLY);
    if (!fd)
        exit(1);
    while (read(fd, &c, 1))
        len++;
    close(fd);	
    missatge = (unsigned char *)malloc(sizeof(unsigned char) * (len));
    fd = open(file, O_RDONLY);
    if (read(fd, missatge, len) < 0)
        exit(1);
    close(fd);

	missatgedecript = malloc (RSA_size(key));	

	RSA_private_decrypt(RSA_size(key), missatge, missatgedecript, key, RSA_PKCS1_PADDING);
	x=0;
	while (missatgedecript[x] != '\n' && missatgedecript[x] != '\0')
        x++;

	printf("\n");
	printf("\nmisssatge codificat:\n%s\n",missatge);
	
	printf("\nmisssatge desxifrat%s\n",missatgedecript);
	printf("\n");
	
	free(missatgedecript);
	free(missatge);
	free(file);
	missatgedecript=NULL;
	missatge=NULL;
	file=NULL;
	
	return(0);
}

int	private(t_rsa *crt_rsa, int k,int i, int j)
{
 BIGNUM *n = BN_new ();
  BIGNUM *d = BN_new ();
  BIGNUM *e = BN_new ();
  BIGNUM *p;
  BIGNUM *q;
  BIGNUM *p1 = BN_new ();
  BIGNUM *q1 = BN_new ();
  BIGNUM *dmp1 = BN_new ();
  BIGNUM *dmq1 = BN_new ();
  BIGNUM *iqmp = BN_new ();
  BIGNUM *phi = BN_new ();
  BN_CTX *ctx = BN_CTX_new ();
  RSA *key = RSA_new ();
  int	result;

  result = 0;
  p = BN_dup(crt_rsa[k].p);
  q = BN_dup(crt_rsa[k].q);
 printf("proba"); 
  if (!(BN_is_prime_ex (p, BN_prime_checks, ctx, NULL)) ||
      !(BN_is_prime_ex (q, BN_prime_checks, ctx, NULL))) {
      printf ("Arguments must both be prime!\n");
      exit (1);
  }

  BN_dec2bn (&e, "65537");

  /* Calculate RSA private key parameters */

  /* n = p*q */
  BN_mul (n, p, q, ctx);
  /* p1 = p-1 */
  BN_sub (p1, p, BN_value_one ());
  /* q1 = q-1 */
  BN_sub (q1, q, BN_value_one ());
  /* phi(pq) = (p-1)*(q-1) */
  BN_mul (phi, p1, q1, ctx);
  /* d = e^-1 mod phi */
  BN_mod_inverse (d, e, phi, ctx);
  /* dmp1 = d mod (p-1) */
  BN_mod (dmp1, d, p1, ctx);
  /* dmq1 = d mod (q-1) */
  BN_mod (dmq1, d, q1, ctx);
  /* iqmp = q^-1 mod p */
  BN_mod_inverse (iqmp, q, p, ctx);

  /* Populate key data structure using RSA_set0 accessor methods */
  RSA_set0_key(key, n, e, d);
  RSA_set0_factors(key, p, q);
  RSA_set0_crt_params(key, dmp1, dmq1, iqmp);

  if (RSA_check_key(key) != 1) {
    printf("OpenSSL reports internal inconsistency in generated RSA key!\n");
    exit(1);
  }

  /* Output the private key in human-readable and PEM forms */
 // RSA_print_fp (stdout, key, 5);
 // printf("\n");
 // PEM_write_RSAPrivateKey (stdout, key, NULL, NULL, 0, 0, NULL);


  desxifratge(&crt_rsa[0], k, key);
  
  
   //Release allocated objects 
  BN_CTX_free (ctx);
 
 
  //BN_clear_free (phi);
 // BN_clear_free (p1);
//  BN_clear_free (q1);
  RSA_free(key); // also frees n, e, d, p, q, dmp1, dmq1, iqmp 
//  BN_clear (p);
 // BN_clear (q);
  BN_clear_free (phi);
  BN_clear_free (p1);
  BN_clear_free (q1);
printf("\nsdaojseiofnojsfdnsjfsdnj\n");

BN_clear(crt_rsa[k].p);
BN_clear(crt_rsa[k].q);

	return(result);
}
int mcd(t_rsa *crt_rsa)
{
	int	n;
	BIGNUM	*a;
	BIGNUM	*b;
	BIGNUM	*c;
	BN_CTX 	*temp;
/*
  certificats crackejables el 29 i 82 i 34 80 i 44 9 i 58 71 i 60 97 i 7 93
*/
//BN_clear(crt_rsa[0].p);
//BN_clear(crt_rsa[1].p);
//BN_clear(crt_rsa[0].q);
//BN_clear(crt_rsa[1].q);

	a = BN_dup(crt_rsa[0].modul);
	b = BN_dup(crt_rsa[1].modul);
	c = BN_new();
	temp = BN_CTX_new();
	
		n = BN_cmp(a, b);


		if ( n == 0)
		{
			//moduls iguals
			BN_clear_free(a);
			BN_clear_free(b);
			if (c)
				BN_clear_free(c);
			return (-1);
		}

	
	while (!BN_is_one(a) && !BN_is_one(b))
	{

		n = BN_cmp(a, b);
	//	printf("\nla n%d\n",n);

		if ( n == 0)
		{
			
			crt_rsa[0].p = BN_dup(a);
			crt_rsa[1].p = BN_dup(a);
			BN_clear(c);
			BN_div(c, NULL,crt_rsa[0].modul, a, temp);
			crt_rsa[0].q = BN_dup(c);
			BN_clear(c);
			BN_div(c, NULL,crt_rsa[1].modul, b, temp);
			crt_rsa[1].q = BN_dup(c);
			//BN_clear(c);
			BN_clear_free(a);
			BN_clear_free(b);
			if (c)
				BN_clear_free(c);

			return (1);
		}
		
		if ( n == -1)
		{
			BN_sub(c, b, a);
			BN_clear(b);
			b = BN_dup(c);
			BN_clear(c);
		}
		if ( n == 1)
		{
			BN_sub(c, a, b);
			BN_clear(a);
			a = BN_dup(c);
			BN_clear(c);
		}
	}
	BN_clear_free(a);
	BN_clear_free(b);
	if (c)
		BN_clear_free(c);
	return(0);
}


void ft_crack(int argc, char *argv[])
{


	t_rsa	crt_rsa[2];
	char *cert_filestr;
	
    EVP_PKEY 	*pkey = NULL;
  	BIO         *certbio = NULL;
  	BIO         *outbio = NULL;
   	RSA			*rsa;
	int			ret;
	char	*temp = NULL;
	char	*temp2 = NULL;
	char	*modul = NULL;
	int		i;
	int		j;

	/* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  i = 1;
	//inicialitzem la estrucura
//	crt_rsa[0].modul=BN_new();
//	crt_rsa[0].p=BN_new();
//	crt_rsa[0].q=BN_new();
	crt_rsa[0].nom=NULL;
	
//	crt_rsa[1].modul=BN_new();
//	crt_rsa[1].p=BN_new();
//	crt_rsa[1].q=BN_new();
	crt_rsa[1].nom=NULL;

	while ( i < argc)
	{
		temp	 = ft_strdup("./");
		cert_filestr = ft_strjoin(temp, argv[i]);
		free(temp);
		//cert_filestr = ft_strjoin(temp2, ".pem");
		//free(temp2);

		/* ---------------------------------------------------------- *
		* Create the Input/Output BIO's.                             *
		* ---------------------------------------------------------- */

		certbio = BIO_new(BIO_s_file());
		outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  		/* ---------------------------------------------------------- *
   		* Load the certidficate from file (PEM).                      *
  		 * ---------------------------------------------------------- */
	//guardem el nom del fitxer
	
		if (crt_rsa[0].nom)
			free(crt_rsa[0].nom);

		crt_rsa[0].nom = ft_strdup(cert_filestr);
	
		ret = BIO_read_filename(certbio, cert_filestr);
	//	printf("nom arxiu pem\n%s\n",cert_filestr);
		free(cert_filestr);

		
		if (! (pkey = PEM_read_bio_PUBKEY(certbio, NULL, 0, NULL))) 
		{
			BIO_printf(outbio, "Error loading cert into memory\n");
    		exit(-1);
  		}
	
  		/* ---------------------------------------------------------- *
   		* Print the public key information and the key in PEM format *
   		* ---------------------------------------------------------- */
  		/* display the key type and size here */

  //		if(!PEM_write_bio_PUBKEY(outbio, pkey))
  //		BIO_printf(outbio, "Error writing public key data in PEM format");


		rsa = EVP_PKEY_get1_RSA(pkey);
		crt_rsa[0].modul = BN_dup(RSA_get0_n(rsa));
    	
		EVP_PKEY_free(pkey);
  		BIO_free_all(certbio);
  		BIO_free_all(outbio);
  		j = i + 1;
		while ( j < argc)
		{
			temp = ft_strdup("./");
			cert_filestr = ft_strjoin(temp, argv[j]);
			free(temp);
			//cert_filestr = ft_strjoin(temp2, ".pem");
			//free(temp2);
	
			/* ---------------------------------------------------------- *
			* Create the Input/Output BIO's.                             *
			* ---------------------------------------------------------- */
	
			certbio = BIO_new(BIO_s_file());
			outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

	  		/* ---------------------------------------------------------- *
	   		* Load the certificate from file (PEM).                      *
	  		 * ---------------------------------------------------------- */
	//afegim el nom arxiu a lestructura
			if (crt_rsa[1].nom)
				free(crt_rsa[1].nom);
			crt_rsa[1].nom = ft_strdup(cert_filestr);
			ret = BIO_read_filename(certbio, cert_filestr);
 			free(cert_filestr);

			if (! (pkey = PEM_read_bio_PUBKEY(certbio, NULL, 0, NULL)))
			{
				BIO_printf(outbio, "Error loading cert into memory\n");
    			exit(-1);
  			}

	  		/* ---------------------------------------------------------- *
	   		* Print the public key information and the key in PEM format *
	   		* ---------------------------------------------------------- */
	  		/* display the key type and size here */
				

			rsa = EVP_PKEY_get1_RSA(pkey);
	 	    crt_rsa[1].modul = BN_dup(RSA_get0_n(rsa));

////////////////MODUL /////////////////////////////////////
/***************/
			if (mcd(&crt_rsa[0])==1)
			{
				printf("\nTrobat!!!!\n");
				printf("\nTrobat!!!!\n");

/*
			modul = BN_bn2dec(crt_rsa[0].p);
	   		printf("\nMCD P:\n%s\n",modul);
			free(modul);

			modul = BN_bn2dec(crt_rsa[0].q);
	  		printf("\nMCD q:\n%s\n",modul);
			free(modul);

			modul = BN_bn2dec(crt_rsa[1].p);
	   		printf("\nMCD segon P:\n%s\n",modul);
			free(modul);

			modul = BN_bn2dec(crt_rsa[1].q);
	  		printf("\nMCD segon q:\n%s\n",modul);
			free(modul);
*/	   	

		//	private(&crt_rsa[0], 0, i, j);
		//	private(&crt_rsa[0], 1, i, j);
					
			}
	
			
			EVP_PKEY_free(pkey);
  			BIO_free_all(certbio);
  			BIO_free_all(outbio);
			if (crt_rsa[1].modul)
				BN_clear(crt_rsa[1].modul);
			j++;
		}
		
		if (crt_rsa[0].modul)
			BN_clear(crt_rsa[0].modul);
		i++;
	} 
	if (crt_rsa[0].p)		
		BN_free(crt_rsa[0].p);
		crt_rsa[0].p=NULL;
	if (crt_rsa[0].q)		
		BN_free(crt_rsa[0].q);
	crt_rsa[0].q=NULL;
	if (crt_rsa[0].nom)		
		free(crt_rsa[0].nom);
	crt_rsa[0].nom=NULL;
	if (crt_rsa[0].modul)		
		BN_free(crt_rsa[0].modul);
	crt_rsa[0].modul=NULL;
	if (crt_rsa[1].modul)		
		BN_free(crt_rsa[1].modul);
	crt_rsa[1].modul=NULL;
	if (crt_rsa[1].p)		
		BN_free(crt_rsa[1].p);		
	crt_rsa[1].p=NULL;
	if (crt_rsa[1].q)		
		BN_free(crt_rsa[1].q);
	crt_rsa[1].q=NULL;
	if (crt_rsa[1].nom)		
		free(crt_rsa[1].nom);
	crt_rsa[1].nom=NULL;

	exit(0);

}

void ft_get_mod_exp(char *argv[])
{
	char *cert_filestr;
    EVP_PKEY 	*pkey = NULL;
  	BIO         *certbio = NULL;
  	BIO         *outbio = NULL;
  	X509        *cert = NULL;
  	RSA			*rsa;
	int			ret;
	char	*temp;

	
	temp = ft_strdup("./");
	cert_filestr = ft_strjoin(temp, argv[1]);
	free(temp);
	 
	/* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  certbio = BIO_new(BIO_s_file());
  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * Load the certificate from file (PEM).                      *
   * ---------------------------------------------------------- */
	ret = BIO_read_filename(certbio, cert_filestr);
	free(cert_filestr);
  if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    BIO_printf(outbio, "Error loading cert into memory\n");
    exit(-1);
  }

  /* ---------------------------------------------------------- *
   * Extract the certificate's public key data.                 *
   * ---------------------------------------------------------- */
  if ((pkey = X509_get_pubkey(cert)) == NULL)
    BIO_printf(outbio, "Error getting public key from certificate");

  /* ---------------------------------------------------------- *
   * Print the public key information and the key in PEM format *
   * ---------------------------------------------------------- */
  /* display the key type and size here */

  if(!PEM_write_bio_PUBKEY(outbio, pkey))
    BIO_printf(outbio, "Error writing public key data in PEM format");

		rsa = EVP_PKEY_get1_RSA(pkey);
	    RSA_print_fp(stdout, rsa, 0);

  EVP_PKEY_free(pkey);
  X509_free(cert);
  BIO_free_all(certbio);
  BIO_free_all(outbio);

  exit(0);
}
int main(int argc, char *argv[])
{

	if (argc < 2)
		printf("arguments erronis");		
	if (argc == 2)
		ft_get_mod_exp(argv);
	if (argc > 2)
		ft_crack(argc,argv);
}
