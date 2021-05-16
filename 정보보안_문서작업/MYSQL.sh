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
echo ' 1.1 기본 계정의 패스워드, 정책 등을 변경하여 사용 '  					>> $CREATE_FILE
echo '======================================================================='	>> $CREATE_FILE
echo '기본 계정 패스워드를 변경하여 사용하도록 권고함' 							>> $CREATE_FILE
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
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '패스워드가 변경 .'							 							>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' 패스워드 확인  =   ' $result1_1 											>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE



echo '============================== 1.2 ===================================='	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 1.2 scott등 Demostration 및 불필요한 계정을 제거하거나 잠금 설정 후 사용'>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '계정 정보를 확인하여 불필요한 계정이 없는 경우'					 		>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '[설정]' 																	>> $CREATE_FILE 
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
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '불필요한 계정 삭제.'						 								>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '계정의 목록화   =   ' $result1_2 											>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE



echo '============================== 1.3 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 1.3 패스워드의 사용기간 및 복잡도 기관 정책에 맞도록 설정'  												>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '패스워드를 주기적으로 변경하고,패스워드 정책이 적용되어 있는 경우[인터뷰]'>> $CREATE_FILE
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
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '패스워드 복잡도 정책 설정'												>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '취약한 패스워드 점검   =   ' $result1_3 									>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE



echo '============================== 1.4 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 1.4 데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 허용'			>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '인가된 계정에게만 관리자 권한이 부여된 경우[인터뷰]'						>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
mysql -u $id -p${pwd} -e "show grants; " -t 									> ./result_set/1-4.txt
cat ./result_set/1-4.txt 														>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'mysql.tables_priv 권한 확인' >>  $CREATE_FILE
mysql -u $id -p${pwd} -e "select * from mysql.tables_priv;" -t >> ./result_set/1-4-1.txt
echo ' ' >> $CREATE_FILE
echo 'mysql.user 권한 확인' >>  $CREATE_FILE
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
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '인가 되지 않은 사용자의 접근 제어 '		 								>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '인가된 계정 점검   =   ' $result1_4										>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 


echo '============================== 1.5 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 1.5 패스워드 재사용에 대한 제약'  												>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '패스워드 재사용 설정 적용 확인'								>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
	result1_5='N/A'
echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '패스워드 재사용 설정 적용' 											>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '계정 목록화   =   ' $result1_5 											>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 





echo '============================== 1.6 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 1.6 사용자별 계정 부여'  												>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '사용자별 계정을 사용하고 있을 경우[인터뷰]'								>> $CREATE_FILE
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
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '사용자에게 최소한의 권한부여' 											>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '계정 목록화   =   ' $result1_6 											>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 




echo '============================== 2.1 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 2.1 원격에서 DB서버로의 접속 제한'  										>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'IP,DB Port가 접근제어 되어 있거나, Default DB Port가 변경되어 있을 경우'	>> $CREATE_FILE
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
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo 'Default DB 포트 변경 혹은 IP 접근 제한 '						 			>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '원격에서 DB서버로의 접속 제한   =   ' $result2_1 							>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 2.2 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 2.2 DBA이외의 인가되지 않은 사용자 시스템 테이블 접근 제한 설정'  		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'DBA만 접근 가능한 테이블에 일반 사용자 접근이 불가능 할 경우'	>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo 'mysql.tables_priv 권한 확인' >>  $CREATE_FILE
mysql -u $id -p${pwd} -e "select * from mysql.tables_priv;" -t >> $CREATE_FILE
echo ' ' >> $CREATE_FILE
echo 'mysql.user 권한 확인' >>  $CREATE_FILE
mysql -u $id -p${pwd} -e "select host, user, select_priv, insert_priv, update_priv, drop_priv, create_priv, reload_priv, shutdown_priv, process_priv, file_priv, grant_priv, references_priv, index_priv, alter_priv, show_db_priv, super_priv, create_tmp_table_priv, lock_tables_priv, execute_priv from mysql.user;" -t >> $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result2_2='Interview'
echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo 'DBA이외의 인가되지 않은 사용자 시스템 테이블 접근 제한   =   ' $result2_2 >> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 2.3 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 2.3 오라클 데이터베이스의 경우 리스너 패스워드 설정'  					>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'listener 패스워드 설정 했을 경우'											>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '해당사항 없음' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result2_3='N/A'
echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo 'listener 패스워드 설정   =   ' $result2_3 								>> 	$CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 




echo '============================== 2.4 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 2.4 불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거'  					>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '불필요한 ODBC/OLE-DB가 설치되지 않은 경우'								>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '해당사항 없음' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result2_4='N/A'
echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '불필요한 ODBC/OLE-DB가 설치   =   ' $result2_4 								>> 	$CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 2.5 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 2.5 일정 횟수의 로그인 실패 시 잠금 정책 설정'  							>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '로그인 실패 시 잠금 정책 설정되지 않은 경우'								>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '해당사항 없음' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result2_5='N/A'
echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '로그인 실패 시 잠금 정책 설정   =   ' $result2_5 								>> 	$CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 


echo '============================== 2.6 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 2.6 데이터베이스의 주요 파일 보호 등을 위해 DB 계정의 umask를 022 이상으로 설정'  							>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'UMASK 값이 022 이면 양호'													>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo "①현재 로그인 계정 UMASK"                                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------"                                        >> $CREATE_FILE 2>&1
umask                                                                                          >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
then
	echo "② /etc/profile 파일(올바른 설정: umask 022)"                                     >> $CREATE_FILE 2>&1
	echo "------------------------------------------------"                                >> $CREATE_FILE 2>&1
	if [ `cat /etc/profile | grep -i "umask" | grep -v "^#" | wc -l` -gt 0 ]
	then
		cat /etc/profile | grep -i "umask" | grep -v "^#"                              >> $CREATE_FILE 2>&1
	else
		echo "＊umask 설정이 없습니다."                                                >> $CREATE_FILE 2>&1
	fi
else
	echo "＊/etc/profile 파일이 없습니다."                                                 >> $CREATE_FILE 2>&1
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
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '계정의 umask를 022 이상   =   ' $result2_6 								>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 


echo '============================== 2.7 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 2.7 데이터베이스의 주요 설정파일, 패스워드 파일 등 주요 파일들의 접근 권한 설정'  >> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '주요 설정 파일 및 디렉터리의 퍼미션 설정이 되어있는 경우'					>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo "my.cnf 퍼미션"                                                            >> $CREATE_FILE 2>&1
echo "------------------------------------------------"                         >> $CREATE_FILE 2>&1
if [ -f /etc/my.cnf ]
then
	ls -alL /etc/my.cnf                                                                    >> $CREATE_FILE 2>&1
else
	echo "＊/etc/my.cnf 파일이 없습니다."                                                 >> $CREATE_FILE 2>&1
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
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '주요 설정 파일 및 디렉터리의 퍼미션 설정   =   ' $result2_7 				>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 2.8 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 2.8 관리자 이외의 사용자가 오라클 리스너의 접속을 통해 리스너 로그 및 trace 파일에 대한 변경 권한 제한'  >> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '파일에 대한 변경 권한 제한'					>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '해당사항 없음' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result2_8='N/A'
echo ' ' 	
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '주요 설정 파일 변경 권한 제한  =   ' $result2_8 				>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 







echo '============================== 3.1 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 3.1 Grant options이 Role에 의해 부여도록 설정' 							>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'DBA 이외의 With Grant Option이 없는 경우'									>> $CREATE_FILE
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
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo 'DBA를 제외한 나머지 계정에게 With Grant  제거 '							>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo 'With Grant Option 제한   =   ' $result3_1 								>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 3.2 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 3.2 OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정'  >> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '원격 사용자 ROLE 설정'					>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '해당사항 없음' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result3_2='N/A'
echo ' ' 	
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '원격 사용자 ROLE 설정 변경 제한  =   ' $result3_2 						>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 3.3 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 3.3 패스워드 확인함수가 설정되어 적용되는가?'  							>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '패스워드 검증 함수로 검증이 진행되는 경우'								>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '해당사항 없음' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result3_3='N/A'
echo ' ' 	
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '패스워드 검증 함수 설정  =   ' $result3_3 								>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 3.4 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 3.4 인가되지 않은 Object Owner가 존재하지 않는가?'  						>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'Object Owner 의 권한이 SYS, SYSTEM, 관리자 계정 등으로 제한된 경우'		>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '해당사항 없음' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result3_4='N/A'
echo ' ' 	
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo 'Object Owner 의 권한 제한  =   ' $result3_4 								>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 3.5 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 3.5 grant option이 role에 의해 부여되도록 설정'  						>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'WITH_GRANT_OPTION이 ROLE에 의하여 설정되어있는 경우'						>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '해당사항 없음' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result3_5='N/A'
echo ' ' 	
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo 'WITH_GRANT_OPTION이 ROLE에 의하여 설정  =   ' $result3_5 					>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 


echo '============================== 3.6 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 3.6 데이터베이스의 자원 제한 기능을 TRUE로 설정'  						>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'RESOURCE_LIMIT 설정이 TRUE로 되어있는 경우'								>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '해당사항 없음' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result3_6='N/A'
echo ' ' 	
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo 'RESOURCE_LIMIT 설정  =   ' $result3_6 									>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 4.1 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 4.1 최신 패치 적용 점검' 												>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo '버전별 최신패치를 적용한 경우'											>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
mysql -u $id -p${pwd} -e "select @@version" -t									> ./result_set/4-1.txt
cat ./result_set/4-1.txt 														>> $CREATE_FILE
result4_1="Interview"

echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '상하반기 업데이트 날짜 확인 '												>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '최신패치 적용 점검      =    ' $result4_1 								>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 4.2 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 4.2 감사기록 설정 '		 												>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'DBMS의 감사 로그 저장 정책이 수립되어 있으며, 정책이 적용되어 있는 경우'	>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
mysql -u $id -p${pwd} -e "show variables like 'general_log%';" -t				> ./result_set/4-2.txt
cat ./result_set/4-2.txt 														>> $CREATE_FILE
result4_2="Interview"

echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '감사로그 설정 '															>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '감사기록설정      =    ' $result4_2 										>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 




echo '============================== 4.3 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 4.3 보안 패치 적용 여부 '		 										>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'DBMS의 최신 패치를 확인하여 패치 예정이 있는지 확인 '						>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '인터뷰 진행'																> ./result_set/4-3.txt
cat ./result_set/4-3.txt 														>> $CREATE_FILE
result4_3="Interview"

echo ' ' 																		>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '상하반기 업데이트 날짜 확인 '												>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '보안 패치 적용 여부      =    ' $result4_3 								>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo ' ' 



echo '============================== 5.1 ====================================' 	>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo ' 5.1 Audit Table은 데이터베이스 관리자 계정에 속해 있도록 설정'  			>> $CREATE_FILE
echo '=======================================================================' 	>> $CREATE_FILE
echo 'Audit Table 접근 권한이 관리자 계정으로 설정한 경우'						>> $CREATE_FILE
echo '' 																		>> $CREATE_FILE
echo '해당사항 없음' >>  $CREATE_FILE

echo '=======================================================================' 	>> $CREATE_FILE
	result5_1='N/A'
echo ' ' 	
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo '[결과]' 																	>> $CREATE_FILE
echo '-----------------------------------------------------------------------'	>> $CREATE_FILE
echo ' ' 																		>> $CREATE_FILE
echo 'Audit Table 접근 권한 설정  =   ' $result5_1 									>> $CREATE_FILE
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
