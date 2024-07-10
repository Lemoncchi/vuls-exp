FROM vulshare/nginx-php-flag
RUN echo "#!/bin/bash\n\
/etc/init.d/nginx start && /etc/init.d/php7.2-fpm start\n\
while true; do sleep 1000; done" > /2.sh