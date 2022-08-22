/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   corsair.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: msoler-e <msoler-e@student.42barcel>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/07/13 14:35:53 by msoler-e          #+#    #+#             */
/*   Updated: 2022/08/03 16:34:51 by msoler-e         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef CORSAIR_H
# define CORSAIR_H

#include <fcntl.h>
# include <stdlib.h>
# include <stdio.h>
# include <unistd.h>
# include <stdarg.h>
# include <limits.h>
# include <string.h>
# include <math.h>
# include <openssl/rsa.h>
# include  <openssl/bn.h>
# include <openssl/engine.h>
# include <openssl/pem.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/bio.h>
# include <openssl/x509.h>

typedef struct s_rsa
{
	char	*path;	
	BIGNUM	*modul;
	BIGNUM	*p ;
	BIGNUM	*q ;
	char	*nom ;
}	t_rsa;

char	*ft_strdup(const char *s);
char	*ft_strjoin(const char *s1, const char *s2);
size_t	ft_strlen(const char *str);
#endif
