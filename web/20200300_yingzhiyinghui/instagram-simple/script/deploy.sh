#!/bin/bash -v

flag1="flag{c0931ce6-6ce8-4d55-ace3-33cb8b44e07c}"
flag2="flag{1d910542-4588-4a6b-9ac2-54e13d39dd3d}"
flag3="flag{5c377290-b08b-4d27-8a0b-ddbd80fcbb5b}"

prompt1="<%\n//你真棒！给你一个flag！\n//${flag1}\n//下一个flag在 /etc/passwd 中，想办法得到它吧~\n%>"
prompt2="#${flag2}\n#下一个flag在/root/flag\n#知道什么是SUID吗？"
prompt3="${flag3}"

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

# add war package
tar zcf ${webapps_path}/ROOT.tgz ${webapps_path}/ROOT && \
rm -rf ${webapps_path}/ROOT && \
# 调用python直接解压
python -c "import zipfile;z=zipfile.ZipFile('./instagram.war');[z.extract(f,'${webapps_path}/ROOT') for f in z.namelist()];z.close();" && \
# chmod war package
chown tomcat ${webapps_path}/ROOT/upload && \
chmod 1644 ${webapps_path}/ROOT/upload/index.jsp && \

# attach to flag.jsp
echo -e ${prompt1} >> ${webapps_path}/ROOT/flag.jsp && \

# 修改/etc/passwd
echo -e ${prompt2} >> /etc/passwd && \

# 修改/usr/bin/tar属性
chmod 4755 /usr/bin/tar && \

# 添加/root/flag
echo -e ${prompt3} > /root/flag && \

# 清理痕迹
rm -rf /root/.bash_history && \

echo "Done. It is recommended to restart system."
