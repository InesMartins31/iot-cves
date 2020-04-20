FROM ubuntu:18.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 software-properties-common
RUN add-apt-repository ppa:ondrej/php -y
RUN apt-get install -y php7.1 php7.1-mysql php7.1-curl php7.1-json php7.1-cgi php7.1-recode php7.1-sq php7.1-intl libapache2-mod-php7.1 php7.1-mcrypt php7.1-xmlrpc php7.1-gd php7.1-mbstring php7.1 php7.1-common php7.1-xmlrpc php7.1-soap php7.1-xml php7.1-intl php7.1-cli php7.1-ldap php7.1-zip php7.1-readline php7.1-imap php7.1-tidy php7.1-fpm
RUN apt-get install -y wget unzip
WORKDIR /home
RUN mkdir -p /var/www/html/soplanning
RUN wget https://netcologne.dl.sourceforge.net/project/soplanning/soplanning/v1.45/soplanning-1-45.zip && \
    unzip soplanning-1-45.zip && \
    cp -r soplanning /var/www/html/soplanning && \
    chown -R www-data.www-data /var/www/html/soplanning && \
    chmod -R 775 /var/www/html/soplanning
ADD example.conf /etc/apache2/sites-available/soplanning.conf
RUN a2ensite soplanning.conf && a2enmod rewrite
RUN echo "root:root" | chpasswd
#CMD apachectl -k start -X
