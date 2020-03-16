#!/bin/bash -v
# 注意，需要使用 bash deploy.sh 的方式运行，而不是 sh deploy.sh

flag="flag{c0931ce6-6ce8-4d55-ace3-33cb8b44e07c}"

prompt="<%/* ${flag} */%>"

robots="User-agent: *\nDisallow: /flag.jsp"


webapps_path="/usr/share/tomcat/webapps"

# yum update
yum update -y && \

# yum install tomcat
yum install -y \
tomcat \
tomcat-admin-webapps \
tomcat-docs-webapp \
tomcat-lib \
tomcat-servlet-3.0-api \
tomcat-webapps && \
systemctl enable tomcat && \
systemctl start tomcat && \

# firewalld
firewall-cmd --zone=public --add-port=8080/tcp --permanent && \
firewall-cmd --zone=public --add-port=8009/tcp --permanent && \
firewall-cmd --zone=public --remove-service=ssh --permanent && \
firewall-cmd --reload && \

# add robots.txt
echo -e ${robots}>${webapps_path}/ROOT/robots.txt && \


# add flag.jsp
echo -e ${prompt}>${webapps_path}/ROOT/flag.jsp && \

# 清理痕迹
rm -rf /root/.bash_history && \

echo "Done. It is recommended to restart system."
