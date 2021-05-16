#!/bin/sh
HOSTNAME=`hostname`
CREATE_FILE=`hostname`_mysql_`date +%y-%m-%d`.txt
LANG=C
export LANG


echo ""																				> $CREATE_FILE
echo "###########################################################################"	>> $CREATE_FILE 
echo "#                       MySQL Vulnerability Checker                       #"	>> $CREATE_FILE 
echo "###########################################################################"	>> $CREATE_FILE 
echo ""																				>> $CREATE_FILE 
echo ""																				>> $CREATE_FILE 
echo '**********************************************************************'
echo '**********************  MySQL Vulnerability Checker  *****************'
echo '****************************** Start *********************************'
echo '**********************************************************************'
date																				>> $CREATE_FILE 
echo ""																				>> $CREATE_FILE 
echo 
echo '[Mysql Admin User/PW]'
echo "    (ex. root/123456) : " 
read -s idpwd
id=`echo $idpwd|awk -F'/' '{print $1}'`
pwd=`echo $idpwd|awk -F'/' '{print $2}'`
space="|                                           |"
rm -rf ./result_set
mkdir ./result_set
#echo $idpwd
#echo $id
#echo ${pwd}

echo "****************************** Start **********************************"	>> $CREATE_FILE 
echo '============================== 1.1 ===================================='	>> $CREATE_FILE
echo '======================================================================='	>> $CREATE_FILE
echo ' 1.1 �⺻ ������ �н�����, ��å ���� �����Ͽ� ��� '  					>> $CREATE_FILE
echo '======================================================================='	>> $CREATE_FILE
echo '�⺻ ���� �н����带 �����Ͽ� ����ϵ��� �ǰ���' 							>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE

mysql -u $id -p${pwd} -e "select host, user, password from mysql.user;" -t 			> ./result_set/1-1.txt
cat ./result_set/1-1.txt 														>> $CREATE_FILE

if [ `cat ./result_set/1-1.txt|grep -v '+'|grep -v password|grep -v '*' |grep -v '|      |' |wc -l` -eq 0 ]
	then
	result1_1='Good'
else
	result1_1='Vulnerability'
fi

echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '�н����尡 ���� .'							 							>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' �н����� Ȯ��  =   ' $result1_1 											>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE



echo '============================== 1.2 ===================================='	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 1.2 scott�� Demostration �� ���ʿ��� ������ �����ϰų� ��� ���� �� ���'>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '���� ������ Ȯ���Ͽ� ���ʿ��� ������ ���� ���'					 		>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '[����]' 																	>> $CREATE_FILE 
mysql -u $id -p${pwd} -e  "select host, user from mysql.user;" -t 				> ./result_set/1-2.txt
cat ./result_set/1-2.txt >> $CREATE_FILE

if [ `cat ./result_set/1-2.txt|grep -v '+'|grep -v user|grep -v root|wc -l` -eq 0 ]
	then
	result1_2='Good'
else
	result1_2='Vulnerability'
fi

echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '���ʿ��� ���� ����.'						 								>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '������ ���ȭ   =   ' $result1_2 											>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE



echo '============================== 1.3 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 1.3 �н������� ���Ⱓ �� ���⵵ ��� ��å�� �µ��� ����'  												>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '�н����带 �ֱ������� �����ϰ�,�н����� ��å�� ����Ǿ� �ִ� ���[���ͺ�]'>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
mysql -u $id -p${pwd} -e "select host, user from mysql.user where password=password(user);" -t > ./result_set/1-3.txt
mysql -u $id -p${pwd} -e "select host, user, password from mysql.user where password='';" -t > ./result_set/1-3.txt
cat ./result_set/1-3.txt >> $CREATE_FILE

if [ `cat ./result_set/1-3.txt|grep -v '+'|grep -v user |grep -v Value |grep -v 0 |wc -l` -eq 0 ]
	then
	result1_3='Good'
else
	result1_3='Vulnerability'
fi

echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '�н����� ���⵵ ��å ����'												>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '����� �н����� ����   =   ' $result1_3 									>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE



echo '============================== 1.4 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 1.4 �����ͺ��̽� ������ ������ �� �ʿ��� ���� �� �׷쿡 ���'			>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '�ΰ��� �������Ը� ������ ������ �ο��� ���[���ͺ�]'						>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
mysql -u $id -p${pwd} -e "show grants; " -t 									> ./result_set/1-4.txt
cat ./result_set/1-4.txt 														>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'mysql.tables_priv ���� Ȯ��' >>  $CREATE_FILE
mysql -u $id -p${pwd} -e "select * from mysql.tables_priv;" -t >> ./result_set/1-4-1.txt
echo ' ' >> $CREATE_FILE
echo 'mysql.user ���� Ȯ��' >>  $CREATE_FILE
mysql -u $id -p${pwd} -e "select host, user, select_priv, insert_priv, update_priv, drop_priv, create_priv, reload_priv, shutdown_priv, process_priv, file_priv, grant_priv, references_priv, index_priv, alter_priv, show_db_priv, super_priv, create_tmp_table_priv, lock_tables_priv, execute_priv from mysql.user;" -t >> ./result_set/1-4-1.txt
cat ./result_set/1-4-1.txt 														>> $CREATE_FILE
if [ `cat ./result_set/1-4.txt|grep -v '+'|grep -v grants |grep -v root |wc -l` -eq 0 ]
	then
	result1_4='Good'
else
	result1_4='Interview'
fi

echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '�ΰ� ���� ���� ������� ���� ���� '		 								>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '�ΰ��� ���� ����   =   ' $result1_4										>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 


echo '============================== 1.5 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 1.5 �н����� ���뿡 ���� ����'  												>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '�н����� ���� ���� ���� Ȯ��'								>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
	result1_5='N/A'
echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '�н����� ���� ���� ����' 											>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '���� ���ȭ   =   ' $result1_5 											>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 





echo '============================== 1.6 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 1.6 ����ں� ���� �ο�'  												>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '����ں� ������ ����ϰ� ���� ���[���ͺ�]'								>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
mysql -u $id -p${pwd} -e "select host, user from mysql.user;" -t 				> ./result_set/1-6.txt

cat ./result_set/1-6.txt >> $CREATE_FILE

if [ `cat ./result_set/1-6.txt|grep -v '+'|grep -v user |grep -v root |wc -l` -ne 0 ]
	then
	result1_6='Good'
else
	result1_6='Interview'
fi

echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '����ڿ��� �ּ����� ���Ѻο�' 											>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '���� ���ȭ   =   ' $result1_6 											>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 




echo '============================== 2.1 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 2.1 ���ݿ��� DB�������� ���� ����'  										>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'IP,DB Port�� �������� �Ǿ� �ְų�, Default DB Port�� ����Ǿ� ���� ���'	>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
mysql -u $id -p${pwd} -e "select host, user from mysql.user where host='%';" -t	> ./result_set/2-1.txt
mysql -u $id -p${pwd} -e "show variables like 'port';" -t						>> ./result_set/2-1.txt
cat ./result_set/2-1.txt 														>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
cat /etc/my.cnf >> $CREATE_FILE
if [ `cat ./result_set/2-1.txt|grep -v '+'|grep -v user |grep -v '%'|grep -v '3306'|wc -l` -ne 0 ]
	then
	result2_1='Good'
else
	result2_1='Vulnerability'
fi

echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo 'Default DB ��Ʈ ���� Ȥ�� IP ���� ���� '						 			>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '���ݿ��� DB�������� ���� ����   =   ' $result2_1 							>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 2.2 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 2.2 DBA�̿��� �ΰ����� ���� ����� �ý��� ���̺� ���� ���� ����'  		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'DBA�� ���� ������ ���̺� �Ϲ� ����� ������ �Ұ��� �� ���'	>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo 'mysql.tables_priv ���� Ȯ��' >>  $CREATE_FILE
mysql -u $id -p${pwd} -e "select * from mysql.tables_priv;" -t >> $CREATE_FILE
echo ' ' >> $CREATE_FILE
echo 'mysql.user ���� Ȯ��' >>  $CREATE_FILE
mysql -u $id -p${pwd} -e "select host, user, select_priv, insert_priv, update_priv, drop_priv, create_priv, reload_priv, shutdown_priv, process_priv, file_priv, grant_priv, references_priv, index_priv, alter_priv, show_db_priv, super_priv, create_tmp_table_priv, lock_tables_priv, execute_priv from mysql.user;" -t >> $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result2_2='Interview'
echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo 'DBA�̿��� �ΰ����� ���� ����� �ý��� ���̺� ���� ����   =   ' $result2_2 >> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 2.3 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 2.3 ����Ŭ �����ͺ��̽��� ��� ������ �н����� ����'  					>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'listener �н����� ���� ���� ���'											>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '�ش���� ����' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result2_3='N/A'
echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo 'listener �н����� ����   =   ' $result2_3 								>> 	$CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 




echo '============================== 2.4 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 2.4 ���ʿ��� ODBC/OLE-DB ������ �ҽ��� ����̺� ����'  					>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '���ʿ��� ODBC/OLE-DB�� ��ġ���� ���� ���'								>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '�ش���� ����' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result2_4='N/A'
echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '���ʿ��� ODBC/OLE-DB�� ��ġ   =   ' $result2_4 								>> 	$CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 2.5 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 2.5 ���� Ƚ���� �α��� ���� �� ��� ��å ����'  							>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '�α��� ���� �� ��� ��å �������� ���� ���'								>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '�ش���� ����' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result2_5='N/A'
echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '�α��� ���� �� ��� ��å ����   =   ' $result2_5 								>> 	$CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 


echo '============================== 2.6 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 2.6 �����ͺ��̽��� �ֿ� ���� ��ȣ ���� ���� DB ������ umask�� 022 �̻����� ����'  							>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'UMASK ���� 022 �̸� ��ȣ'													>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo "������ �α��� ���� UMASK"                                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------"                                        >> $CREATE_FILE 2>&1
umask                                                                                          >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
then
	echo "�� /etc/profile ����(�ùٸ� ����: umask 022)"                                     >> $CREATE_FILE 2>&1
	echo "------------------------------------------------"                                >> $CREATE_FILE 2>&1
	if [ `cat /etc/profile | grep -i "umask" | grep -v "^#" | wc -l` -gt 0 ]
	then
		cat /etc/profile | grep -i "umask" | grep -v "^#"                              >> $CREATE_FILE 2>&1
	else
		echo "��umask ������ �����ϴ�."                                                >> $CREATE_FILE 2>&1
	fi
else
	echo "��/etc/profile ������ �����ϴ�."                                                 >> $CREATE_FILE 2>&1
fi
echo '=======================================================================' 	>> $CREATE_FILE
if [ `umask` -ge 22 ]
	then
	result2_6='Good'
else
	result2_6='Vulnerability'
fi
echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '������ umask�� 022 �̻�   =   ' $result2_6 								>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 


echo '============================== 2.7 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 2.7 �����ͺ��̽��� �ֿ� ��������, �н����� ���� �� �ֿ� ���ϵ��� ���� ���� ����'  >> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '�ֿ� ���� ���� �� ���͸��� �۹̼� ������ �Ǿ��ִ� ���'					>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo "my.cnf �۹̼�"                                                            >> $CREATE_FILE 2>&1
echo "------------------------------------------------"                         >> $CREATE_FILE 2>&1
if [ -f /etc/my.cnf ]
then
	ls -alL /etc/my.cnf                                                                    >> $CREATE_FILE 2>&1
else
	echo "��/etc/my.cnf ������ �����ϴ�."                                                 >> $CREATE_FILE 2>&1
fi
echo '=======================================================================' 	>> $CREATE_FILE
if [ -f /etc/my.cnf ]
  then
  if [ `ls -alL /etc/my.cnf |grep "..--------" | wc -l` -eq 1 ]
    then
    result2_7='Good'
    else
    result2_7='Vulnerability'
  fi
  else
  result2_7='Vulnerability'
fi
echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '�ֿ� ���� ���� �� ���͸��� �۹̼� ����   =   ' $result2_7 				>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 2.8 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 2.8 ������ �̿��� ����ڰ� ����Ŭ �������� ������ ���� ������ �α� �� trace ���Ͽ� ���� ���� ���� ����'  >> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '���Ͽ� ���� ���� ���� ����'					>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '�ش���� ����' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result2_8='N/A'
echo ' ' 	
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '�ֿ� ���� ���� ���� ���� ����  =   ' $result2_8 				>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 







echo '============================== 3.1 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 3.1 Grant options�� Role�� ���� �ο����� ����' 							>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'DBA �̿��� With Grant Option�� ���� ���'									>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
mysql -u $id -p${pwd} -e "select host, user, grant_priv from mysql.user;" -t	> ./result_set/3-1.txt
cat ./result_set/3-1.txt 														>> $CREATE_FILE

if [ `cat ./result_set/3-1.txt|grep -v '+'|grep -v user |grep -v root|grep -v N |wc -l` -eq 0 ]
	then
	result3_1='Good'
else
	result3_1='Vulnerability'
fi

echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo 'DBA�� ������ ������ �������� With Grant  ���� '							>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo 'With Grant Option ����   =   ' $result3_1 								>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 3.2 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 3.2 OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES�� FALSE�� ����'  >> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '���� ����� ROLE ����'					>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '�ش���� ����' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result3_2='N/A'
echo ' ' 	
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '���� ����� ROLE ���� ���� ����  =   ' $result3_2 						>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 3.3 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 3.3 �н����� Ȯ���Լ��� �����Ǿ� ����Ǵ°�?'  							>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '�н����� ���� �Լ��� ������ ����Ǵ� ���'								>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '�ش���� ����' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result3_3='N/A'
echo ' ' 	
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '�н����� ���� �Լ� ����  =   ' $result3_3 								>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 3.4 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 3.4 �ΰ����� ���� Object Owner�� �������� �ʴ°�?'  						>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'Object Owner �� ������ SYS, SYSTEM, ������ ���� ������ ���ѵ� ���'		>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '�ش���� ����' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result3_4='N/A'
echo ' ' 	
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo 'Object Owner �� ���� ����  =   ' $result3_4 								>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 3.5 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 3.5 grant option�� role�� ���� �ο��ǵ��� ����'  						>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'WITH_GRANT_OPTION�� ROLE�� ���Ͽ� �����Ǿ��ִ� ���'						>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '�ش���� ����' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result3_5='N/A'
echo ' ' 	
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo 'WITH_GRANT_OPTION�� ROLE�� ���Ͽ� ����  =   ' $result3_5 					>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 


echo '============================== 3.6 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 3.6 �����ͺ��̽��� �ڿ� ���� ����� TRUE�� ����'  						>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'RESOURCE_LIMIT ������ TRUE�� �Ǿ��ִ� ���'								>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '�ش���� ����' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result3_6='N/A'
echo ' ' 	
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo 'RESOURCE_LIMIT ����  =   ' $result3_6 									>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 4.1 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 4.1 �ֽ� ��ġ ���� ����' 												>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '������ �ֽ���ġ�� ������ ���'											>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
mysql -u $id -p${pwd} -e "select @@version" -t									> ./result_set/4-1.txt
cat ./result_set/4-1.txt 														>> $CREATE_FILE
result4_1="Interview"

echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '���Ϲݱ� ������Ʈ ��¥ Ȯ�� '												>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '�ֽ���ġ ���� ����      =    ' $result4_1 								>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 4.2 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 4.2 ������ ���� '		 												>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'DBMS�� ���� �α� ���� ��å�� �����Ǿ� ������, ��å�� ����Ǿ� �ִ� ���'	>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
mysql -u $id -p${pwd} -e "show variables like 'general_log%';" -t				> ./result_set/4-2.txt
cat ./result_set/4-2.txt 														>> $CREATE_FILE
result4_2="Interview"

echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '����α� ���� '															>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '�����ϼ���      =    ' $result4_2 										>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 




echo '============================== 4.3 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 4.3 ���� ��ġ ���� ���� '		 										>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'DBMS�� �ֽ� ��ġ�� Ȯ���Ͽ� ��ġ ������ �ִ��� Ȯ�� '						>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '���ͺ� ����'																> ./result_set/4-3.txt
cat ./result_set/4-3.txt 														>> $CREATE_FILE
result4_3="Interview"

echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '���Ϲݱ� ������Ʈ ��¥ Ȯ�� '												>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '���� ��ġ ���� ����      =    ' $result4_3 								>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 5.1 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 5.1 Audit Table�� �����ͺ��̽� ������ ������ ���� �ֵ��� ����'  			>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'Audit Table ���� ������ ������ �������� ������ ���'						>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '�ش���� ����' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result5_1='N/A'
echo ' ' 	
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[���]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo 'Audit Table ���� ���� ����  =   ' $result5_1 									>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 


rm -rf result.tar.gz
tar -zcvf result.tar.gz result_set $CREATE_FILE &>/dev/null
rm -rf mysql_result.tx*
rm -rf result_set
echo 'Result File : result.tar.gz'										
echo '**********************************************************************'
echo '****************************** End ***********************************'
echo '**********************************************************************'
echo '****************************** End ***********************************' 	>> $CREATE_FILE

#end script
