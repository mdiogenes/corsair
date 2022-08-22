/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utl_corsair.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: msoler-e <msoler-e@student.42barcel>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/07/27 11:16:21 by msoler-e          #+#    #+#             */
/*   Updated: 2022/08/01 17:28:43 by msoler-e         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "corsair.h"

size_t	ft_strlcat(char *dst, const char *src, size_t sizedstmem)
{
	size_t	x;
	size_t	y;
	size_t	sizesrc;
	size_t	sizedst;
	char	*s;

	x = 0;
	s = (char *) src;
	sizesrc = ft_strlen(src);
	sizedst = ft_strlen(dst);
	y = sizedst;
	if (sizedstmem == 0)
		return (sizesrc);
	if (sizedst < sizedstmem -1)
	{
		while ((sizedst + x) < (sizedstmem - 1) && s[x] != '\0')
		{
			dst[y++] = s[x++];
		}
		dst[y] = '\0';
	}	
	if (sizedstmem <= sizedst)
		return (sizesrc + sizedstmem);
	return (sizesrc + sizedst);
}

size_t	ft_strlcpy(char *dst, const char *src, size_t sizedst)
{
	size_t			sizesrc;
	unsigned int	x;

	sizesrc = ft_strlen(src);
	x = 0;
	if (sizedst != 0)
	{
		while ((src[x] != '\0') && (x < (sizedst - 1)))
		{
			dst[x] = src[x];
			x++;
		}
		dst[x] = '\0';
	}
	return (sizesrc);
}

size_t	ft_strlen(const char *str)
{
	size_t	cont;
	int		i;

	i = 0;
	if (str[i] == '\0')
		return (0);
	cont = 0;
	while (str[i] != '\0')
	{
		cont ++;
		i++;
	}
	return (cont);
}
char	*ft_strjoin(const char *s1, const char *s2)
{
	char			*dst;
	unsigned int	sizes1;
	unsigned int	sizes2;
	int				lendst;

	if (!s1 || !s2)
		return (0);
	sizes1 = ft_strlen((char *)s1);
	sizes2 = ft_strlen((char *)s2);
	dst = (char *)malloc(sizeof (const char) * (sizes1 + sizes2 + 1));
	if (dst == 0)
		return (0);
	lendst = ft_strlcpy(dst, s1, (sizes1 + 1));
	lendst = ft_strlcat(dst, s2, (sizes1 + sizes2 + 1));
	return (dst);
}

char	*ft_strdup(const char *s)
{
	int		i;
	int		len;
	char	*str;

	len = 0;
	while (s[len])
		len ++;
	str = (char *)malloc(sizeof(const char) * (len + 1));
	if (!str)
		return (0);
	str[0] = '\0';
	i = 0;
	while (i < len)
	{
		str[i] = s[i];
		i ++;
	}
	str[i] = '\0';
	return (str);
}

