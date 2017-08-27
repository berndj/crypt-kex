
BINARY=diffie
SOURCE=diffie.c


CC=gcc


$CC $CFLAGS -Wall -Werror -g $SOURCE -o $BINARY -lcrypto
[ $? -ne 0 ] || ./$BINARY

while inotifywait -e modify $SOURCE
do
$CC $CFLAGS -Wall -Werror -g $SOURCE -o $BINARY -lcrypto
[ $? -ne 0 ] || ./$BINARY

done
