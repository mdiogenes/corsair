NAME		=	corsair

OBJS		=	${SRC:.c=.o}

CC			=	gcc

RM			=	rm -f

all:		${NAME}

$(NAME):	
			$(CC) -o $(NAME) utl_corsair.c corsair.c /Users/msoler-e/.brew/opt/openssl@1.1/lib/libcrypto.a /Users/msoler-e/.brew/opt/openssl@1.1/lib/libssl.a -I/Users/msoler-e/.brew/opt/openssl@1.1/include

clean:
			$(RM) $(OBJS)

fclean:		clean
			$(RM) $(NAME)

re:			fclean all
