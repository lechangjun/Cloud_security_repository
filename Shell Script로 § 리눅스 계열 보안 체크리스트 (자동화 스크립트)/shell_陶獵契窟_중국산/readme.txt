脚本说明：
   1.将本目录所有文件都放入到一台自己的本地linux主机同一目录下
   2.将服务器IP、普通账号、普通账号密码、root密码依次按以下格式写入到hosts.txt中（注意“~”作为hosts.txt的分隔符）：

192.168.1.81~user~123456~nothing
192.168.1.10~user~123456~nothing
192.168.1.11~user~123456~nothing

   3.执行sh login.sh,脚本将自动批量上传checklinux.sh到服务器/tmp目录下，并且自动执行和自动上传结果到本地linux主机上
   4.最后将服务器上传的脚本和结果自动删除


http://www.freebuf.com/sectool/123094.html

(注意：本脚本适用于linux系统)
