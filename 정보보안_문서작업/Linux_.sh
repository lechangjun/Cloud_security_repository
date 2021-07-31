#!/bin/sh

# Linux Vulnerability Scanner

rm -rf /tmp/lee/tmp
mkdir -p /tmp/lee/tmp
TMP=/tmp/lee/tmp



HOSTNAME=`hostname`
LANG=C
export LANG
clear
CREATE_FILE=`hostname`_Linux_`date +%y-%m-%d`.txt
echo " "										       	>> $CREATE_FILE 2>&1
echo "" 										       	>> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "##################################  Start Time  #######################################" >> $CREATE_FILE 2>&1
date                                                                                           >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "=============================  LINUX Security Check  ==============================" 	   >> $CREATE_FILE 2>&1
echo "=============================  LINUX Security Check  ==============================" 
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "*************************************** START *****************************************" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                                     1. 계정 관리                                      " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "U-01 START"                                                                              
echo "U-01 START"                                                                              >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                             1.01 root 계정 원격 접속 제한                             " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준1: /etc/securetty 파일에 pts/* 설정이 있으면 무조건취약"                          >> $CREATE_FILE 2>&1 
echo "■ 기준2: /etc/securetty 파일에 pts/* 설정이 없거나 주석처리가 되어 있고,"                >> $CREATE_FILE 2>&1 
echo "■        : /etc/pam.d/login에서 auth required /lib/security/pam_securetty.so 라인에 주석(#)이 없으면 양호" >> $CREATE_FILE 2>&1
echo "        (1)ssh 서비스 미사용 시 양호"                                                    >> $CREATE_FILE 2>&1
echo "        (2)ssh 서비스 사용 시 config 파일의 PermitRootlogin 옵션 no 적용 양호"           >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "*************************************주의사항******************************************" >> $CREATE_FILE 2>&1
echo "서비스 실행 여부 판단을 특정 포트로 하는 경우 실제 사용 하는 포트와 다를 수 있습니다. "  >> $CREATE_FILE 2>&1
echo "ex) *.23 LISTEN 일 경우 Telnet을 사용하는 것으로 판단 하나 실제로 23번에 MySql DB를"     >> $CREATE_FILE 2>&1
echo "사용 할 수 도 있으므로 실제로 WellKnown 포트를 사용 하는지 확인 해야함"                  >> $CREATE_FILE 2>&1
echo "*************************************주의사항******************************************" >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 telnet포트 확인"                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/services ]
  then
  cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp"                >> $CREATE_FILE 2>&1
  else
  echo "* /etc/services 파일이 존재하지 않습니다."					       						>> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "①-① /etc/ssh/sshd_config 파일에서 ssh포트 확인"                                        >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo "** netstat -tnlp 명령어를 활용한 ssh 포트 확인(일치하는지 확인)"					       >> $CREATE_FILE 2>&1
netstat -tnlp | grep -v 127.0.0.1 | sed 's/:::/0 /g' | sed 's/[:\/]/ /g' | awk '{print $5"\t"$10}' | sort -ug | grep sshd >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/ssh/sshd_config ]
  then
  if [ `cat /etc/ssh/sshd_config | grep -i "port [0-9]" | grep -v "Gateway" | grep -v "^#" | wc -l` -eq 1 ]
    then
      cat /etc/ssh/sshd_config | grep -i "port [0-9]" | grep -v "Gateway" | grep -v "^#"             >> $CREATE_FILE 2>&1
    else
      cat /etc/ssh/sshd_config | grep -i "port [0-9]" | grep -v "Gateway"			                   >> $CREATE_FILE 2>&1
    fi
  else
    echo "* /etc/ssh/sshd_config 파일이 존재하지 않습니다."				       				   >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "② 서비스 포트 활성화 여부 확인"                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo "[telnet 활성화 여부 확인]"                                                               >> $CREATE_FILE 2>&1

if [ `cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -eq 1 ]
then
	if [ -f /etc/services ]
	then
	  port=`cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	  if [ `netstat -na | grep ":$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	  then
		  netstat -na | grep ":$port " | grep -i "LISTEN" | head -1                     >> $CREATE_FILE 2>&1	
	  else
		  echo "＊Telnet 서비스 미사용 중입니다."                                        >> $CREATE_FILE 2>&1
	  fi
	else
	echo "* /etc/services 파일이 존재하지 않습니다."				         >> $CREATE_FILE 2>&1
	fi
else
	echo "＊Telnet 서비스 미사용 중입니다."                                                >> $CREATE_FILE 2>&1
fi



echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[ssh 활성화 여부 확인]"                                                                  >> $CREATE_FILE 2>&1
if [ `ps -ef | grep -i "ssh" | grep -v "grep" | wc -l` -ge 1 ]
then	
	if [ -f /etc/ssh/sshd_config ]
	then
	  if [ `cat /etc/ssh/sshd_config | grep -i "port [0-9]" | grep -v "Gateway" | grep -v "^#" | wc -l` -eq 1 ]
	  then
	    cat /etc/ssh/sshd_config | grep -i "port [0-9]" | grep -v "Gateway" | grep -v "^#" > 1.01_1.txt
	    sed -e "s/Port//g" -e "s/ //g" 1.01_1.txt > 1.01_2.txt
	  else
	    cat /etc/ssh/sshd_config | grep -i "port [0-9]" | grep -v "Gateway" > 1.02_1.txt
	    sed -e "s/Port//g" -e "s/#//g" -e "s/ //g" 1.01_1.txt > 1.01_2.txt
	  fi
	    
	  
	  sshport=`cat 1.01_2.txt`
	  if [ `netstat -na | grep ":$sshport" | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	  then
		  netstat -na | grep ":$sshport" | grep -i "LISTEN" | head -1                      		>> $CREATE_FILE 2>&1		
		  echo " "                                                                       		>> $CREATE_FILE 2>&1
		  echo "②-① /etc/ssh/sshd_config 설정확인"                                            >> $CREATE_FILE 2>&1
		  echo "------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1	
		  cat /etc/ssh/sshd_config | grep -i "PermitRootLogin" | grep -v "password"             >> $CREATE_FILE 2>&1
					
	  else
		  echo "＊ssh 서비스 미사용 중입니다."                                         			>> $CREATE_FILE 2>&1
		  echo 442
	  fi
	
	
	else
	  echo "* /etc/ssh/sshd_config 파일이 존재하지 않습니다."									>> $CREATE_FILE 2>&1
	fi
else
	echo "＊ssh 서비스 미사용 중입니다."                                                    	>> $CREATE_FILE 2>&1
fi


echo "③-① /etc/securetty 파일 설정"                                                             >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/securetty | grep "pts" | wc -l` -gt 0 ]
then
	cat /etc/securetty | grep "pts"                                                        >> $CREATE_FILE 2>&1
else
	echo "/etc/securetty 파일에 pts/0~pts/x 설정이 없습니다."                              >> $CREATE_FILE 2>&1
fi


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③-② /etc/pam.d/login 파일 설정"                                                           >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/pam.d/login | grep "pam_securetty.so"                                                 >> $CREATE_FILE 2>&1
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


if [ `cat /etc/securetty | awk '$1=="pts" {print $1}' | wc -l` -eq 0 ]
then
	if [ `cat /etc/pam.d/login | grep -v "^#" | grep "pam_securetty.so" | wc -l` -eq 0 ]
	then
		echo "[1.01] 취약"							       >> $CREATE_FILE 2>&1
	else
		echo "[1.01] 양호"							       >> $CREATE_FILE 2>&1
	fi
else
     echo "[1.01] 취약"										>> $CREATE_FILE 2>&1							
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-01 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-01 END"
unset port
unset sshport
rm -rf 1.01_1.txt
rm -rf 1.01_2.txt
rm -rf 1.01_3.txt
rm -rf 1.01_4.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       




echo "U-02 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-02 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                               1.02 패스워드 복잡성 설정                               " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 영문 숫자 특수문자가 혼합된 8자리 이상의 패스워드가 설정된 경우 양호"            >> $CREATE_FILE 2>&1 
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
then
  echo "① /etc/passwd 파일"                                                                    >> $CREATE_FILE 2>&1
  echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
  cat /etc/passwd | head -3 >> $TMP/1.02_1.txt
  echo "...중략..."         >> $TMP/1.02_1.txt						       
  cat /etc/passwd | tail -3 >> $TMP/1.02_1.txt
  cat $TMP/1.02_1.txt									       >> $CREATE_FILE 2>&1
else
  echo "＊/etc/passwd 파일이 없습니다."                                                        >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/shadow ]
then
  echo "② /etc/shadow 파일"                                                                    >> $CREATE_FILE 2>&1
  echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
  cat /etc/shadow | head -3 >> $TMP/1.02_2.txt
  echo "...중략..."         >> $TMP/1.02_2.txt
  cat /etc/shadow | tail -3 >> $TMP/1.02_2.txt
  cat $TMP/1.02_2.txt									       >> $CREATE_FILE 2>&1
else
  echo "＊/etc/shadow 파일이 없습니다."                                                        >> $CREATE_FILE 2>&1
fi
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1

echo " "										       >> $CREATE_FILE 2>&1
echo "[1.02] 수동점검" 									       >> $CREATE_FILE 2>&1
echo " "										       >> $CREATE_FILE 2>&1
echo "U-02 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-02 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-03 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-03 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                               1.03 계정 잠금 임계값 설정                              " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/pam.d/system-auth 파일에 아래와 같은 설정이 있으면 양호"                    >> $CREATE_FILE 2>&1
echo "■       : (auth required /lib/security/pam_tally.so deny=5 unlock_time=120 no_magic_root)" >> $CREATE_FILE 2>&1
echo "■       : (account required /lib/security/pam_tally.so no_magic_root reset)"             >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       										   >> $CREATE_FILE 2>&1
echo "K@A@"										       										   >> $CREATE_FILE 2>&1
echo "① /etc/pam.d/system-auth 파일 설정(auth, account)"                                      >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/pam.d/system-auth | grep -E "auth|account"                                            >> $CREATE_FILE 2>&1
echo "A@K@"																					   >> $CREATE_FILE 2>&1
echo "@@@@"																					   >> $CREATE_FILE 2>&1
if [ `cat /etc/pam.d/system-auth | grep -E "auth|account" | grep -v "^#" | grep "deny=[1-5]" | wc -l` -eq 0 ]
then
	echo "[1.03] 취약" 																		   >> $CREATE_FILE 2>&1
else
	echo "[1.03] 양호"		 															   	   >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-03 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-03 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "



echo "U-04 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-04 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                               1.04 패스워드 파일 보호                                 " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 패스워드가 /etc/shadow 파일에 암호화 되어 저장되고 있으면 양호"                  >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
then
  echo "① /etc/passwd 파일"                                                                    >> $CREATE_FILE 2>&1
  echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
  cat /etc/passwd | head -3 >> $TMP/1.04_1.txt
  echo "...중략..."         >> $TMP/1.04_1.txt						       
  cat /etc/passwd | tail -3 >> $TMP/1.04_1.txt
  cat $TMP/1.04_1.txt									       >> $CREATE_FILE 2>&1
else
  echo "/etc/passwd 파일이 없습니다."                                                          >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/shadow ]
then
  echo "② /etc/shadow 파일"                                                                    >> $CREATE_FILE 2>&1
  echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
  cat /etc/shadow | head -3 >> $TMP/1.04_2.txt
  echo "...중략..."         >> $TMP/1.04_2.txt
  cat /etc/shadow | tail -3 >> $TMP/1.04_2.txt
  cat $TMP/1.04_2.txt									       >> $CREATE_FILE 2>&1
else
  echo "/etc/shadow 파일이 없습니다."                                                          >> $CREATE_FILE 2>&1
fi
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "										       >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
then
	if [ `awk -F: '$2=="x"' /etc/passwd | wc -l` -eq 0 ]
	then
		echo "[1.04] 취약"   		            				       >> $CREATE_FILE 2>&1
	else
		echo "[1.04] 양호"   		            				       >> $CREATE_FILE 2>&1
	fi
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-04 END"                                                                                >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-04 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-05 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-05 START"                                                                              
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                           1.05 root 이외의 UID가 '0' 금지                             " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: root 계정만이 UID가 0이면 양호"                                                  >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
then
  awk -F: '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd                                       >> $CREATE_FILE 2>&1
else
  echo "＊/etc/passwd 파일이 존재하지 않습니다."                                               >> $CREATE_FILE 2>&1
fi
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `cat /etc/passwd | awk -F: '$3==0 {print $3}' | wc -l` -eq 1 ]
  then
    echo "[1.05] 양호"									       >> $CREATE_FILE 2>&1
  else
    echo "[1.05] 취약"									       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-05 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-05 END"                                                                                
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       




echo "U-06 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-06 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                                 1.06 root 계정 su 제한                                " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준 : 아래 설정이 없거나, 주석 처리가 되어 있을 경우 su 명령 파일의 권한이 4750 이면 양호"  >> $CREATE_FILE 2>&1
echo "■      : (auth  required  /lib/security/pam_wheel.so debug group=wheel) 또는"          >> $CREATE_FILE 2>&1
echo "■      : (auth  required  /lib/security/\$ISA/pam_wheel.so use_uid)"                   >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1

flag_1_06=1

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
echo "① /etc/pam.d/su 파일 설정"                                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/su ]
then
	cat /etc/pam.d/su								       >> $CREATE_FILE 2>&1
	if [ `cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust' | grep -v "^#" | grep -v "^ *$" | wc -l` -eq 0 ]
	then
		echo "pam_wheel.so 설정 내용이 없습니다."                                      >> $CREATE_FILE 2>&1
		flag_1_06=0
	else
		cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust'                      >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/pam.d/su 파일을 찾을 수 없습니다."                                          >> $CREATE_FILE 2>&1
	flag_1_06=0
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② su 파일권한"                                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `which su | grep -v 'no ' | wc -l` -eq 0 ]
then
	echo "su 명령 파일을 찾을 수 없습니다."                                                >> $CREATE_FILE 2>&1
	flag_1_06=0
else
	sucommand=`which su`;
	ls -alL $sucommand                                                                     >> $CREATE_FILE 2>&1
	sugroup=`ls -alL $sucommand | awk '{print $4}'`;

fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ su 명령그룹"                                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/su ]
then
	if [ `cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust' | grep 'group' | awk -F"group=" '{print $2}' | awk -F" " '{print $1}' | wc -l` -gt 0 ]
	then
		pamsugroup=`cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust' | grep 'group' | awk -F"group=" '{print $2}' | awk -F" " '{print $1}'`
		echo "- su명령 그룹(PAM모듈): `grep -E "^$pamsugroup" /etc/group`"              >> $CREATE_FILE 2>&1
	else
		if [ `cat /etc/pam.d/su | grep 'pam_wheel.so' | egrep -v 'trust|#' | wc -l` -gt 0 ]
		then
			echo "- su명령 그룹(PAM모듈): `grep -E "^wheel" /etc/group`"            >> $CREATE_FILE 2>&1
		fi
	fi
fi
echo "- su명령 그룹(명령파일): `grep -E "^$sugroup" /etc/group`"                               >> $CREATE_FILE 2>&1
echo "A@K@"											>> $CREATE_FILE 2>&1
echo "@@@@"											>> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


if [ $flag_1_06 -eq 1 ]
then
  echo "[1.06] 양호"								               >> $CREATE_FILE 2>&1
else
  echo "[1.06] 취약"								               >> $CREATE_FILE 2>&1
fi


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-06 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-06 END"
unset sucommand
unset sugroup
unset flag_1_06
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       




echo "U-07 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-07 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                             1.07 패스워드 최소 길이 설정                              " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 패스워드 최소 길이가 8자 이상으로 설정되어 있으면 양호"                          >> $CREATE_FILE 2>&1 
echo "■       : (PASS_MIN_LEN 8 이상이면 양호)"                                                >> $CREATE_FILE 2>&1 
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

flag_1_07=1

echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
if [ -f /etc/login.defs ]
  then
    grep -v '^ *#' /etc/login.defs | grep -i "PASS_MIN_LEN"				       >> $CREATE_FILE 2>&1
  else
    echo "/etc/login.defs 파일이 존재하지 않음 " 					       >> $CREATE_FILE 2>&1
    flag_1_07=0
fi
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "										       >> $CREATE_FILE 2>&1


if [ $flag_1_07 -eq 1 ]
then
  if [ `cat /etc/login.defs | grep -i "PASS_MIN_LEN" | grep -v "#" | egrep [0-9]| awk '{print $2}'| wc -l` -eq 0 ]
    then
      echo "[1.07] 취약" 									       >> $CREATE_FILE 2>&1
    else
      if [ `cat /etc/login.defs | grep -i "PASS_MIN_LEN" | grep -v "#" | awk '{print $2}'` -ge 8 ]
        then
          echo "[1.07] 양호" 								       >> $CREATE_FILE 2>&1
        else
          echo "[1.07] 취약" 								       >> $CREATE_FILE 2>&1
      fi
  fi
else
  echo "[1.07] 취약"								               >> $CREATE_FILE 2>&1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-07 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-07 END"
unset flag_1_07
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-08 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-08 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                             1.08 패스워드 최대 사용기간 설정                          " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 패스워드 최대 사용기간이 90일 이하로 설정되어 있으면 양호"                       >> $CREATE_FILE 2>&1 
echo "■       : (PASS_MAX_DAYS 90 이하이면 양호)"                                              >> $CREATE_FILE 2>&1 
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1

flag_1_08=1

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1


if [ -f /etc/login.defs ]
  then
    grep -v '^ *#' /etc/login.defs | grep -i "PASS_MAX_DAYS" 				       >> $CREATE_FILE 2>&1
  else
    echo " /etc/login.defs 파일이 존재하지 않음 " 					       >> $CREATE_FILE 2>&1
    flag_1_08=0
fi


echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " " 										       >> $CREATE_FILE 2>&1


if [ $flag_1_08 -eq 1 ]
then
  if [ `cat /etc/login.defs | grep -i "PASS_MAX_DAYS" | grep -v "#" | egrep  [0-9]| awk  '{print $2}'| wc -l ` -eq 0 ]
   then
      echo "[1.08] 취약"									       >> $CREATE_FILE 2>&1
   else
     if [ `cat /etc/login.defs | grep -i "PASS_MAX_DAYS" | grep -v "#" | awk '{print $2}'` -le 90 ]
      then
       echo "[1.08] 양호"									       >> $CREATE_FILE 2>&1
      else
       echo "[1.08] 취약"									       >> $CREATE_FILE 2>&1
     fi
  fi
else
  echo "[1.08] 취약"								               >> $CREATE_FILE 2>&1
fi 

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-08 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-08 END"
unset flag_1_08
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-09 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-09 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                             1.09 패스워드 최소 사용기간 설정                          " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 패스워드 최소 사용기간이 1일로 설정되어 있으면 양호"                             >> $CREATE_FILE 2>&1
echo "■       : (PASS_MIN_DAYS 1 이상이면 양호)"                                               >> $CREATE_FILE 2>&1 
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1

flag_1_09=1

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       											>> $CREATE_FILE 2>&1
echo "K@A@"										       											>> $CREATE_FILE 2>&1


if [ -f /etc/login.defs ]
  then
    grep -v '^ *#' /etc/login.defs | grep -i "PASS_MIN_DAYS" 									>> $CREATE_FILE 2>&1
  else
    echo " /etc/login.defs 파일이 존재하지 않음 " 												>> $CREATE_FILE 2>&1
    flag_1_09=0
fi


echo "A@K@"																						>> $CREATE_FILE 2>&1
echo "@@@@"										        										>> $CREATE_FILE 2>&1
echo " " 										        										>> $CREATE_FILE 2>&1


if [ $flag_1_09 -eq 1 ]
then
  if [ `cat /etc/login.defs | grep -i "PASS_MIN_DAYS" | egrep [1-9] | grep -v "#" | awk '{print $2}' | wc -l` -eq 0 ]
   then
     echo "[1.09] 취약" 									       >> $CREATE_FILE 2>&1
   else
    if [ `cat /etc/login.defs | grep -i "PASS_MIN_DAYS" | grep -v "#" | awk '{print $2}'` -ge 1 ]
     then
       echo "[1.09] 양호" 								       >> $CREATE_FILE 2>&1
     else
       echo "[1.09] 취약" 								       >> $CREATE_FILE 2>&1
    fi
  fi
else
  echo "[1.09] 취약"								               >> $CREATE_FILE 2>&1
fi


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-09 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-09 END"
unset flag_1_09
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-10 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-10 START" 
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                                1.10 불필요한 계정 제거                                " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/passwd 파일에 lp, uucp, nuucp 계정이 모두 제거되어 있으면 양호"             >> $CREATE_FILE 2>&1
echo "        다른 계정을 확인 하고 싶으면 소스코드 수정"                                      >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
if [ `cat /etc/passwd | egrep "^lp|^uucp|^nuucp" | wc -l` -eq 0 ]
then
  echo "☞ lp, uucp, nuucp 계정이 존재하지 않습니다."                                          >> $CREATE_FILE 2>&1
else
  cat /etc/passwd | egrep "^lp|^uucp|^nuucp" | grep -v "^#"                                     >> $TMP/1.10.txt
  cat $TMP/1.10.txt																			>> $CREATE_FILE 2>&1
fi
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "   										       >> $CREATE_FILE 2>&1

if [ -f $TMP/1.10.txt ]
then 
	if [ `cat $TMP/1.08.txt | awk -F: '{if ($7=="/sbin/nologin" || $7=="/bin/false") print $0 }' | wc -l` -gt 0 ]
	then
     echo "[1.10] 양호" 								       >> $CREATE_FILE 2>&1                                          
	else
	 echo "[1.10] 취약" 								       >> $CREATE_FILE 2>&1                                          
	fi
else
     echo "[1.10] 양호" 							               >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-10 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-10 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       




echo "U-11 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-11 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                         1.11 관리자 그룹에 최소한의 계정 포함                         " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 관리자 계정이 포함된 그룹에 불필요한 계정이 존재하지 않는 경우 양호"             >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
echo "① 관리자 계정"                                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
then
  awk -F: '$1=="root" { print $1 " -> GID=" $4 }' /etc/passwd                                  >> $CREATE_FILE 2>&1
else
  echo "/etc/passwd 파일이 없습니다."                                                          >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 관리자 계정이 포함된 그룹 확인"                                                       >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
awk -F: '$3==0 {print $0}' /etc/group							       >> $CREATE_FILE 2>&1
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "										       >> $CREATE_FILE 2>&1
cat /etc/group | awk -F: '$3==0 {print $4}' > $TMP/1.09_1.txt
sed "s/root//g" $TMP/1.11_1.txt > $TMP/1.11_2.txt
if [ `cat $TMP/1.11_2.txt | wc -w` -eq 0 ]
then
    echo "[1.11] 양호"		 						               >> $CREATE_FILE 2>&1
else
    echo "[1.11] 취약" 									       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-11 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-11 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-12 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-12 START" 
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                          1.12 계정이 존재하지 않는 GID 금지                           " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 구성원이 존재하지 않는 빈 그룹이 발견되지 않을 경우 양호"                        >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

flag_1_12=1

echo "!@#$"										        									   >> $CREATE_FILE 2>&1
echo "K@A@"										       										   >> $CREATE_FILE 2>&1
# 소유자가 만들어 놓고 계정이 삭제된 파일은 GID -> 101 가고 UID -> other 로 바뀐다.
# 그래서 다른 일반 사용자가 X 권한을 사용 할 수 있게 된다.
echo "① 구성원이 존재하지 않는 그룹"                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1

cat /etc/passwd | grep -v "^#" | awk -F: '{print $1"::"$4}' > 1.12_1.txt

cat /etc/group | grep -v "^#" | awk -F: '$4==null {print $1"::"$3}' > 1.12_2.txt

diff 1.12_1.txt 1.12_2.txt | grep -i "^<"	> 1.12_3.txt
diff 1.12_1.txt 1.12_2.txt | grep -i "^>"	>> 1.12_3.txt
sed -e "s/<//g" -e "s/>//g" -e "s/ //g" 1.12_3.txt 	> 1.12_4.txt

diff 1.12_1.txt 1.12_4.txt | grep -i "^>" > 1.12_5.txt
sed -e "s/>//g" -e "s/ //g" 1.12_5.txt 	  > 1.12_6.txt



if [ `cat 1.12_6.txt | wc -l` -eq 0 ]
then
	echo "＊구성원이 존재하지 않는 그룹이 발견되지 않았습니다."                                >> $CREATE_FILE 2>&1
else
	cat 1.12_6.txt                                           							       >> $CREATE_FILE 2>&1
	flag_1_12=0
fi
echo "A@K@"										       										   >> $CREATE_FILE 2>&1
echo "@@@@"										       										   >> $CREATE_FILE 2>&1
echo " "										       										   >> $CREATE_FILE 2>&1     

if [ $flag_1_12 -eq 1 ]
then
    echo "[1.12] 양호" 								               							   >> $CREATE_FILE 2>&1
else
    echo "[1.12] 수동점검" 									       								   >> $CREATE_FILE 2>&1
fi


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-12 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-12 END"
rm -rf 1.12_1.txt
rm -rf 1.12_2.txt
rm -rf 1.12_3.txt
rm -rf 1.12_4.txt
rm -rf 1.12_5.txt
rm -rf 1.12_6.txt
unset flag_1_12
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-13 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-13 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                                 1.13 동일한 UID 금지                                  " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 동일한 UID로 설정된 계정이 존재하지 않을 경우 양호"                              >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
echo "① 동일한 UID를 사용하는 계정 "                                                           >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo " " > $TMP/1.13_1.txt
for uid in `cat /etc/passwd | awk -F: '{print $3}'`
do
	cat /etc/passwd | awk -F: '$3=="'${uid}'" { print "UID=" $3 " -> " $1 }' > $TMP/1.13_2.txt
	if [ `cat $TMP/1.13_2.txt | wc -l` -gt 1 ]
	then
		cat $TMP/1.13_2.txt  >> $TMP/1.13_1.txt
	fi
done
if [ `sort -k 1 $TMP/1.13_1.txt | wc -l` -gt 1 ]
then
	sort -k 1 $TMP/1.13_1.txt | uniq -d                                                         >> $CREATE_FILE 2>&1
else
	echo "＊동일한 UID를 사용하는 계정이 발견되지 않았습니다."                             >> $CREATE_FILE 2>&1
fi
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


if [ `sort -k 1 $TMP/1.13_1.txt | uniq -d | wc -l` -le 1 ]
then
    echo "[1.13] 양호" 								               >> $CREATE_FILE 2>&1
else
    echo "[1.13] 취약"		 							       >> $CREATE_FILE 2>&1
fi


echo " "										       >> $CREATE_FILE 2>&1
echo "U-13 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-13 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " " 




echo "U-14 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-14 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                                1.14 사용자 Shell 점검                                 " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 로그인이 필요하지 않은 시스템 계정에 /bin/false(nologin) 쉘이 부여되어 있으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       										   >> $CREATE_FILE 2>&1
echo "K@A@"										       										   >> $CREATE_FILE 2>&1
echo "＊ 로그인이 필요하지 않은 시스템 계정 확인"                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
  then
    cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" | grep -v "^#" >> $TMP/1.14.txt
	cat $TMP/1.14.txt 									       								   >> $CREATE_FILE 2>&1
  else
    echo "/etc/passwd 파일이 없습니다."                                                        >> $CREATE_FILE 2>&1
fi
echo "A@K@"										       										   >> $CREATE_FILE 2>&1
echo "@@@@"										       										   >> $CREATE_FILE 2>&1
echo " "   										       										   >> $CREATE_FILE 2>&1
# &&는 앞의 명령어가 실행되고 뒤의 명령어를 실행시키고 싶을때, || 앞의 명령어가 실패하고 뒤의 명령어를 실행시키고 싶을때
if [ `cat $TMP/1.14.txt | awk -F: '{if ($7!="/sbin/nologin" && $7!="/bin/false") print $0 }' | wc -l` -eq 0 ]
then
echo "[1.14] 양호"							                       							   >> $CREATE_FILE 2>&1
else
echo "[1.14] 취약"							                       							   >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-14 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-14 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-15 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-15 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                               1.15 Session Timeout 설정                               " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/profile 에서 timeout=600 또는 /etc/csh.login 에서 autologout=5 로 설정되어 있으면 양호" >> $CREATE_FILE 2>&1
echo "■       : (1) sh, ksh, bash 쉘의 경우 /etc/profile 파일 설정을 적용받음"                 >> $CREATE_FILE 2>&1
echo "■       : (2) csh, tcsh 쉘의 경우 /etc/csh.cshrc 또는 /etc/csh.login 파일 설정을 적용받음" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       											>> $CREATE_FILE 2>&1
echo "K@A@"										       											>> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
then
  echo "① /etc/profile 파일 timeout 설정"                                                                  >> $CREATE_FILE 2>&1
  echo "------------------------------------------------"                                      >> $CREATE_FILE 2>&1
  if [ `cat /etc/profile | grep -Ei "timeout|tmout" | grep -v "^#"  | wc -l` -gt 0 ]
  then
  	cat /etc/profile | grep -Ei "timeout|tmout" | grep -v "^#"                                            >> $CREATE_FILE 2>&1
	flag_1_15=1
  else
  	echo "timeout 이 설정되어 있지 않습니다."                                                    >> $CREATE_FILE 2>&1
	flag_1_15=0
  fi
else
  echo "/etc/profile 파일이 없습니다."                                                         >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ -f /etc/csh.login ]
then
  echo "② /etc/csh.login 파일"                                                                >> $CREATE_FILE 2>&1
  echo "------------------------------------------------"                                      >> $CREATE_FILE 2>&1
  if [ `cat /etc/csh.login | grep -i autologout | grep -v "^#" | wc -l` -gt 0 ]
  then
   	cat /etc/csh.login | grep -i autologout | grep -v "^#"                                     >> $CREATE_FILE 2>&1
	
  else
   	echo "autologout 이 설정되어 있지 않습니다."                                               >> $CREATE_FILE 2>&1
	
  fi
else
  echo "/etc/csh.login 파일이 없습니다."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/csh.cshrc ]
then
  echo "③ /etc/csh.cshrc 파일"                                                                >> $CREATE_FILE 2>&1
  echo "------------------------------------------------"                                      >> $CREATE_FILE 2>&1
  if [ `cat /etc/csh.cshrc | grep -i autologout | grep -v "^#" | wc -l` -gt 0 ]
  then
  	cat /etc/csh.cshrc | grep -i autologout | grep -v "^#"                                     >> $CREATE_FILE 2>&1
	
  else
  	echo "autologout 이 설정되어 있지 않습니다."                                               >> $CREATE_FILE 2>&1
	
  fi
else
  echo "/etc/csh.cshrc 파일이 없습니다."                                                       >> $CREATE_FILE 2>&1
fi

echo "A@K@"																					   >> $CREATE_FILE 2>&1
echo "@@@@"																					   >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $flag_1_15 -eq 1 ] 
  then
    echo "[1.15] 양호"																			>> $CREATE_FILE 2>&1
  else
    echo "[1.15] 취약"																			>> $CREATE_FILE 2>&1
fi

echo " "      																					>> $CREATE_FILE 2>&1
echo "U-15 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-15 END"
unset flag_1_15
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-16 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-16 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                     1.16 root 홈, 패스 디렉터리 권한 및 패스 설정                     " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: Path 설정에 “.” 이 맨 앞이나 중간에 포함되어 있지 않을 경우 양호"                >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
echo "＊PATH 설정 확인"                                                                        >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo $PATH                                                                                     >> $CREATE_FILE 2>&1
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
## &&는 앞의 명령어가 실행되고 뒤의 명령어를 실행시키고 싶을때, || 앞의 명령어가 실패하고 뒤의 명령어를 실행시키고 싶을때
if [ `echo $PATH | grep "\.:" | wc -l` -eq 0 ] && [ `echo $PATH | grep "::" | wc -l` -eq 0 ]
then
echo "[1.16] 양호"								               >> $CREATE_FILE 2>&1
else
echo "[1.16] 취약"									       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-16 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-16 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                               2. 파일 및 디렉터리 관리                                " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "U-17 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-17 START - longtime"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                          2.01 파일 및 디렉터리 소유자 설정                            " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 소유자가 존재하지 않은 파일 및 디렉토리가 존재하지 않을 경우 양호"               >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       										   >> $CREATE_FILE 2>&1
echo "K@A@"										       										   >> $CREATE_FILE 2>&1
echo "＊소유자가 존재하지 않는 파일 (소유자 => 파일위치: 경로)"                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -d /etc ]
then
find /etc \( -nouser -o -nogroup \) -xdev -exec ls -al {} \; 2> /dev/null >> $TMP/2.01.txt
fi
if [ -d /var ]
then
find /var \( -nouser -o -nogroup \) -xdev -exec ls -al {} \; 2> /dev/null >> $TMP/2.01.txt
fi
if [ -d /tmp ]
then
find /tmp \( -nouser -o -nogroup \) -xdev -exec ls -al {} \; 2> /dev/null >> $TMP/2.01.txt
fi
if [ -d /home ]
then
find /home \( -nouser -o -nogroup \) -xdev -exec ls -al {} \; 2> /dev/null >> $TMP/2.01.txt
fi
if [ -d /export ]
then
find /export \( -nouser -o -nogroup \) -xdev -exec ls -al {} \; 2> /dev/null >> $TMP/2.01.txt
fi
cat $TMP/2.01.txt                                                                                >> $CREATE_FILE 2>&1
if [ -s $TMP/2.01.txt ]
then
:
else
echo "＊소유자가 존재하지 않는 파일이 발견되지 않았습니다."                            	       	 >> $CREATE_FILE 2>&1
fi
echo "A@K@"										       											>> $CREATE_FILE 2>&1
echo "@@@@"										       											>> $CREATE_FILE 2>&1
echo " "  										       											>> $CREATE_FILE 2>&1
if [ -s $TMP/2.01.txt ]
then
echo "[2.01] 취약" 		  							       										>> $CREATE_FILE 2>&1
else
echo "[2.01] 양호"									       										>> $CREATE_FILE 2>&1
fi
echo " "             	                                                                       >> $CREATE_FILE 2>&1
echo "U-17 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-17 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " " 




echo "U-18 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-18 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                       2.02 /etc/passwd 파일 소유자 및 권한 설정                       " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/passwd 파일의 소유자가 root 이고, 권한이 644이면 양호"                      >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
# /etc/passwd 파일 존재유무 확인
if [ -f /etc/passwd ]
then
	ls -alL /etc/passwd                                                                    >> $CREATE_FILE 2>&1
else
	echo "＊/etc/passwd 파일이 없습니다."                                                  >> $CREATE_FILE 2>&1
fi
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
# /etc/passwd 파일 존재유무 확인
if [ -f /etc/passwd ]
  then
  # 권한 644 이하인지 확인
  if [ `ls -alL /etc/passwd | egrep "root" | grep ".r.-.--.--" | wc -l` -eq 1 ]
    then
    echo "[2.02] 양호" 									       >> $CREATE_FILE 2>&1
    else
    echo "[2.02] 취약" 									       >> $CREATE_FILE 2>&1
  fi
  else
  echo "[2.02] 취약" 									       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-18 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-18 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-19 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-19 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                       2.03 /etc/shadow 파일 소유자 및 권한 설정                       " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/shadow 파일의 소유자가 root 이고, 권한이 400 이면 양호"                     >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
if [ -f /etc/shadow ]
then
	ls -alL /etc/shadow                                                                    >> $CREATE_FILE 2>&1
else
	echo "＊/etc/shadow 파일이 없습니다."                                                 >> $CREATE_FILE 2>&1
fi
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "										       >> $CREATE_FILE 2>&1
if [ -f /etc/shadow ]
  then
  if [ `ls -alL /etc/shadow |egrep "root" |grep "..--------" | wc -l` -eq 1 ]
    then
    echo "[2.03] 양호"									       >> $CREATE_FILE 2>&1
    else
    echo "[2.03] 취약"									       >> $CREATE_FILE 2>&1
  fi
  else
  echo "[2.03] 취약"									       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1                                                                                      
echo "U-19 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-19 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-20 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-20 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                       2.04 /etc/hosts 파일 소유자 및 권한 설정                        " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/hosts 파일의 소유자가 root 이고, 권한이 644 이면 양호"                      >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
if [ -f /etc/hosts ]
then
	ls -alL /etc/hosts                                                                     >> $CREATE_FILE 2>&1
else
	echo "＊/etc/hosts 파일이 없습니다."                                                   >> $CREATE_FILE 2>&1
fi
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/hosts ]
  then
  if [ `ls -alL /etc/hosts | egrep "root" | grep "...-.--.--" | wc -l` -eq 1 ]
    then
    echo "[2.04] 양호"									       >> $CREATE_FILE 2>&1
    else
    echo "[2.04] 취약"									       >> $CREATE_FILE 2>&1
  fi
  else
  echo "[2.04] 취약"									       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-20 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-20 END"                                                                                
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " " 




echo "U-21 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-21 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                       2.05 /etc/(x)inetd.conf 파일 소유자 및 권한 설정                " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/(x)inetd.conf 파일 및 /etc/xinetd.d/ 하위 모든 파일의 소유자가 root 이고, 권한이 600 이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
flag_2_5=1
echo "① /etc/xinetd.conf 파일"                                                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/xinetd.conf ]
then
	ls -al /etc/xinetd.conf																		>> $CREATE_FILE 2>&1
	if [ `ls -alL /etc/xinetd.conf |egrep "root" | grep "...-------" | wc -l` -eq 1 ]
    then
        :
    else
        flag_2_5=0
    fi
else
    echo "/etc/xinetd.conf 파일이 없습니다."													>> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② /etc/xinetd.d/ 파일"                                                                  >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ls /etc/xinetd.d | wc -l` -gt 1 ]
then
	ls -al /etc/xinetd.d/																		>> $CREATE_FILE 2>&1
	if [ `ls -alL /etc/xinetd.d/ |egrep "root" | grep "...-------" | wc -l` -eq 1 ]	
    then
        :
    else
        :
    fi
else
	echo "/etc/xinetd.d/ 하위 파일이 없습니다."                                               >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ /etc/inetd.conf 파일"                                                                 >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/inetd.conf ]
then
	ls -alL /etc/inetd.conf                                                                      >> $CREATE_FILE 2>&1
	if [ `ls -alL /etc/inetd.conf |egrep "root" | grep "...-------" | wc -l` -eq 1 ]	
    then
        :
    else
        flag_2_5=0
    fi
else
	echo "/etc/inetd.conf 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
fi
echo "A@K@"																					   >> $CREATE_FILE 2>&1
echo "@@@@"																					   >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $flag_2_5 -eq 1 ] 
  then
    echo "[2.05] 양호"										>> $CREATE_FILE 2>&1
  else
    echo "[2.05] 취약"										>> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-21 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-21 END"                                                                                
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-22 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-22 START" 
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                     2.06 /etc/syslog.conf 파일 소유자 및 권한 설정                    " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/(r)syslog.conf 파일의 소유자가 root 이고, 파일의 권한이 644 이면 양호"      >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1

####################################좀더생각해보기##################################################################
#if [ -f /etc/syslog.conf ]
#then
# ls -alL /etc/syslog.conf                                                                     >> $CREATE_FILE 2>&1
#elif [ -f /etc/rsyslog.conf ]
#then
# ls -alL /etc/rsyslog.conf                                                                    >> $CREATE_FILE 2>&1
#else
#echo "＊/etc/syslog.conf 및 /etc/rsyslog.conf파일이 없습니다."                                >> $CREATE_FILE 2>&1
#fi
# 2개 OR 조건으로 확인하기
#if [ -f /etc/syslog.conf ]
#then
#  if [ `ls -alL /etc/syslog.conf | egrep "root" | grep ".r.-.--.--" | wc -l` -eq 1 ] 
#  then
#  echo "[2.06] 양호"									       >> $CREATE_FILE 2>&1
#  else
#  echo "[2.06] 취약"									       >> $CREATE_FILE 2>&1
#  fi
#elif [ -f /etc/rsyslog.conf ]
#then
#  if [ `ls -alL /etc/rsyslog.conf | egrep "root" | grep ".r.-.--.--" | wc -l` -eq 1 ]
#  then
#  echo "[2.06] 양호"								               >> $CREATE_FILE 2>&1
#  else
#  echo "[2.06] 취약"								               >> $CREATE_FILE 2>&1
#  fi  								       
#else
#  echo "[2.06] 취약"									       >> $CREATE_FILE 2>&1
#fi
###################################################################################################################


echo "① syslog 권한 설정 확인"                                                                 >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/syslog.conf ]
then
	ls -alL /etc/syslog.conf                                                                       >> $CREATE_FILE 2>&1
	if [ `ls -alL /etc/syslog.conf | egrep "root" | grep "...-.--.--" | wc -l` -eq 1 ]	
	then
		flag_2_6_1=1
	else
		flag_2_6_1=0
	fi
else
	echo "＊/etc/syslog.conf 파일이 없습니다."                                             >> $CREATE_FILE 2>&1
	flag_2_6_1=0
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② rsyslog 권한 설정 확인"                                                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/rsyslog.conf ]
then
	ls -alL /etc/rsyslog.conf                                                                      >> $CREATE_FILE 2>&1
	if [ `ls -alL /etc/rsyslog.conf | egrep "root" | grep "...-.--.--" | wc -l` -eq 1 ]	
	then
		flag_2_6_2=1
	else
		flag_2_6_2=0
	fi
else
	echo "＊/etc/rsyslog.conf 파일이 없습니다."                                            >> $CREATE_FILE 2>&1
	flag_2_6_2=0
fi
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


if [ $flag_2_6_1 -eq 1 ] || [ $flag_2_6_2 -eq 1 ] 
  then
    echo "[2.06] 양호"										>> $CREATE_FILE 2>&1
  else
    echo "[2.06] 취약"										>> $CREATE_FILE 2>&1
fi


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-22 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-22 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-23 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-23 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                      2.07 /etc/services 파일 소유자 및 권한 설정                      " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/services 파일의 소유자가 root 이고, 파일의 권한이 644 이면 양호"            >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1

if [ -f /etc/services  ]
then
	ls -alL /etc/services                                                                  >> $CREATE_FILE 2>&1
else
	echo "＊/etc/services  파일이 없습니다."                                               >> $CREATE_FILE 2>&1
fi

echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "     										       >> $CREATE_FILE 2>&1
if [ -f /etc/services ]
then
  if [ `ls -alL /etc/services | egrep "root" | grep "...-.--.--" | wc -l` -eq 1 ]	
    then
    echo "[2.07] 양호"							                       >> $CREATE_FILE 2>&1
    else
    echo "[2.07] 취약"							                       >> $CREATE_FILE 2>&1
  fi
else		
  echo "[2.07] 취약"								               >> $CREATE_FILE 2>&1
fi


echo " "     										       >> $CREATE_FILE 2>&1
echo "U-23 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-23 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-24 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-24 START - longtime"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                        2.08 SUID,SGID,Stick bit 설정 파일 점검                        " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 불필요한 SUID/SGID 설정이 존재하지 않을 경우 양호"                               >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
find /usr -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -exec ls -al  {}  \;     >> $TMP/2.08.txt 2>/dev/null	
find /bin -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -exec ls -al  {}  \;     >> $TMP/2.08.txt 2>/dev/null	
if [ -s $TMP/2.08.txt ]
then
	#맨 마지막에 참고로 해서 찍도록 하자 지금은 그냥 주석만 처리 함
	#cat 2.08-1.txt                                                                        >> $CREATE_FILE 2>&1
:
else
	echo "＊ SUID/SGID로 설정된 파일이 발견되지 않았습니다."                               >> $CREATE_FILE 2>&1
fi
echo ----------SUID/SGID 설정이 불필요한 파일----------					       >> $CREATE_FILE 2>&1
# sh 파일 여러줄 이어 쓰고 싶을 때 \ 붙여주면 된다.
check="/usr/bin/admintool /usr/dt/bin/dtprintinfo /usr/sbin/arp /usr/bin/at /usr/dt/bin/sdtcm_convert /usr/sbin/lpmove /usr/bin/atq /usr/lib/fs/ufs/ufsdump /usr/sbin/prtconf /usr/bin/atrm \
/usr/lib/fs/ufs/ufsrestore /usr/sbin/sysdef /usr/bin/lpset /usr/lib/lp/bin/netpr /usr/sbin/sparcv7/prtconf /usr/bin/newgrp /usr/openwin/bin/ff.core /usr/sbin/sparcv7/sysdef /usr/bin/nispasswd \ 
/usr/openwin/bin/kcms_calibrate /usr/sbin/sparcv9/prtconf /usr/bin/rdist /usr/openwin/bin/kcms_configure /usr/sbin/sparcv9/sysdef /usr/bin/yppasswd /usr/openwin/bin/xlock /usr/dt/bin/dtappgather /usr/platform/sun4u/sbin/prtdiag"
if [ -f $TMP/2.08.txt ]
	then
		ls -al $check >> $CREATE_FILE 2>/dev/null	
		flag_2_08=0
	else
		echo "＊파일이 발견되지 않았습니다." >> $CREATE_FILE 2>&1
		flag_2_08=1
fi
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $flag_2_08 -eq 1 ]
  then
    echo "[2.08] 양호"										>> $CREATE_FILE 2>&1
  else
    echo "[2.08] 취약"										>> $CREATE_FILE 2>&1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-24 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-24 END"
#맨 마지막에 지우도록 하자 지금은 그냥 주석처리만
#rm -rf 2.08-1.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-25 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-25 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "             2.09 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정              " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 홈디렉터리 환경변수 파일에 타사용자 쓰기 권한이 제거되어 있으면 양호"            >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
echo "＊ 홈디렉터리 환경변수 파일"                                                             >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "#"`
FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"

for file in $FILES
  do
    FILE=$file
    if [ -f $FILE ]
      then
        ls -alL $FILE >> $CREATE_FILE 2>&1
    fi
  done

for dir in $HOMEDIRS
do
  for file in $FILES
  do
    FILE=$dir/$file
    if [ -f $FILE ]
      then
        ls -alL $FILE >> $CREATE_FILE 2>&1
    fi
  done
done
echo " " >> $CREATE_FILE 2>&1

echo " " > $TMP/2.09.txt

HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "#"`
FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .exrc .netrc"

for file in $FILES
          do
            if [ -f $file ]
             then
             if [ `ls -alL $file | awk '{print $1}' | grep "........-." | wc -l` -eq 1 ]
              then               
                echo "양호" >> $TMP/2.09.txt
              else
                echo "취약" >> $TMP/2.09.txt          
             fi
            else
              echo "양호" >> $TMP/2.09.txt
            fi                                         
         done

 for dir in $HOMEDIRS
    do
         for file in $FILES
          do
            if [ -f $dir/$file ]
             then
             if [ `ls -dal $dir/$file | awk '{print $1}' | grep "........-." | wc -l` -eq 1 ]
              then
                echo "양호" >> $TMP/2.09.txt
              else                
                echo "취약" >> $TMP/2.09.txt
             fi
            else
              echo "양호" >> $TMP/2.09.txt
            fi                                         
         done
    done

echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
	
if [ `cat $TMP/2.09.txt | grep "취약" | wc -l` -eq 0 ]
 then 
  echo "[2.09] 양호" >> $CREATE_FILE 2>&1
 else 
  echo "[2.09] 취약" >> $CREATE_FILE 2>&1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-25 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-25 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       




echo "U-26 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-26 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                            2.10 world writable 파일 점검                              " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 불필요한 권한이 부여된 world writable 파일이 존재하지 않을 경우 양호"            >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
if [ -d /etc ]
then
  find /etc -perm -2 -ls | awk '$11!=null {print $3 " : " $5 " : " $6 " : " $11}' | grep -v "^l" | grep -v "lrwxrwxrwx" | grep -v "srwxrwxrwx" | grep -v "srw-rw-rw-" | grep -v "crw"  > $TMP/2.10.txt
fi
if [ -d /var ]
then
  find /var -perm -2 -ls | awk '$11!=null {print $3 " : " $5 " : " $6 " : " $11}' | grep -v "^l" | grep -v "lrwxrwxrwx" | grep -v "srwxrwxrwx" | grep -v "srw-rw-rw-" | grep -v "crw"  >> $TMP/2.10.txt
fi
if [ -d /tmp ]
then
  find /tmp -perm -2 -ls | awk '$11!=null {print $3 " : " $5 " : " $6 " : " $11}' | grep -v "^l" | grep -v "lrwxrwxrwx" | grep -v "srwxrwxrwx" | grep -v "srw-rw-rw-" | grep -v "crw"  >> $TMP/2.10.txt
fi
if [ -d /home ]
then
  find /home -perm -2 -ls | awk '$11!=null {print $3 " : " $5 " : " $6 " : " $11}'| grep -v "^l" | grep -v "lrwxrwxrwx" | grep -v "srwxrwxrwx" | grep -v "srw-rw-rw-" | grep -v "crw"  >> $TMP/2.10.txt
fi
if [ -d /export ]
then
  find /export -perm -2 -ls | awk '$11!=null {print $3 " : " $5 " : " $6 " : " $11}' | grep -v "^l" | grep -v "lrwxrwxrwx" | grep -v "srwxrwxrwx" | grep -v "srw-rw-rw-" | grep -v "crw" >> $TMP/2.10.txt
fi

if [ -s $TMP/2.10.txt ]
then
  cat $TMP/2.10.txt | head -5                                        			       >> $CREATE_FILE 2>&1
  echo "...중략..."									       >> $CREATE_FILE 2>&1
  cat $TMP/2.10.txt | tail -5                                        			       >> $CREATE_FILE 2>&1
else
  echo "＊World Writable 권한이 부여된 파일이 발견되지 않았습니다."                            >> $CREATE_FILE 2>&1
fi
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "                      								       >> $CREATE_FILE 2>&1
if [ -s $TMP/2.10.txt ]
then
  echo "[2.10] 취약" 									       >> $CREATE_FILE 2>&1
else
  echo "[2.10] 양호" 									       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-26 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-26 END"
#rm -rf 2.10.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-27 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-27 START" - longtime
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                      2.11 /dev에 존재하지 않는 device 파일 점검                       " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준 : dev 에 존재하지 않은 Device 파일을 점검하고, 존재하지 않은 Device을 제거 했을 경우 양호" >> $CREATE_FILE 2>&1
echo "■        : (아래 나열된 결과는 major, minor Number를 갖지 않는 파일임)"                  >> $CREATE_FILE 2>&1
echo "■        : (.devlink_db_lock/.devfsadm_daemon.lock/.devfsadm_synch_door/.devlink_db는 Default로 존재 예외)" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
find /dev -type f -exec ls -l {} \;                                                            > $TMP/2.11.txt

if [ -s $TMP/2.11.txt ]
then
	cat $TMP/2.11.txt                                                                           >> $CREATE_FILE 2>&1
else
	echo "＊dev 에 존재하지 않은 Device 파일이 발견되지 않았습니다."                       >> $CREATE_FILE 2>&1
fi
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "  										       >> $CREATE_FILE 2>&1
if [ -s $TMP/2.11.txt ]
then
  echo "[2.11] 취약" 									       >> $CREATE_FILE 2>&1
else
  echo "[2.11] 양호" 									       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-27 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-27 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " " 




echo "U-28 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-28 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                        2.12 HOME/.rhosts, hosts.equiv 사용 금지                       " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: r-commands 서비스를 사용하지 않으면 양호"                                        >> $CREATE_FILE 2>&1
echo "■       : r-commands 서비스를 사용하는 경우 HOME/.rhosts, hosts.equiv 설정확인"          >> $CREATE_FILE 2>&1
echo "■       : (1) .rhosts 파일의 소유자가 해당 계정의 소유자이고, 퍼미션 600, 내용에 + 가 설정되어 있지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■       : (2) /etc/hosts.equiv 파일의 소유자가 root 이고, 퍼미션 600, 내용에 + 가 설정되어 있지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "										       											>> $CREATE_FILE 2>&1
echo "*************************************주의사항******************************************" >> $CREATE_FILE 2>&1
echo "서비스 실행 여부 판단을 특정 포트로 하는 경우 실제 사용 하는 포트와 다를 수 있습니다. "  >> $CREATE_FILE 2>&1
echo "ex) *.23 LISTEN 일 경우 Telnet을 사용하는 것으로 판단 하나 실제로 23번에 MySql DB를"     >> $CREATE_FILE 2>&1
echo "사용 할 수 도 있으므로 실제로 WellKnown 포트를 사용 하는지 확인 해야함"                  >> $CREATE_FILE 2>&1
echo "*************************************주의사항******************************************" >> $CREATE_FILE 2>&1
flag_2_12_1=1
flag_2_12_2=1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
FILES="/.rhosts"
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
echo "① 서비스 포트 활성화 여부 확인"                             >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		flag_2_12_1=0
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		flag_2_12_1=0
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		flag_2_12_1=0
	fi
fi

if [ $flag_2_12_1 -eq 1 ]
      then
        echo "＊r-commands Service Disable"                                                    	    >> $CREATE_FILE 2>&1
else
for dir in $HOMEDIRS
   do
     for file in $FILES
     do
       if [ -f $dir$file ]
       then
        echo " -> $dir/.rhosts 파일 권한" >> $CREATE_FILE 2>&1
        ls -al $dir$file  >> $CREATE_FILE 2>&1
        echo " " >> $CREATE_FILE 2>&1
       fi
      done
   done
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/hosts.equiv ]
  then
    if [ `ls -al /etc/hosts.equiv | awk '{print $1}' | grep ".rw-------" | wc -l` -eq 1 ]
	  then
	    :
	  else
	    flag_2_12_2=0
	fi
  else
    echo "☞ /etc/hosts.equiv 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	flag_2_12_2=0
fi
echo "● 사용자 home directory .rhosts 설정 내용" >> $CREATE_FILE 2>&1

   for dir in $HOMEDIRS
   do
     for file in $FILES
     do
       if [ -f $dir$file ]
       then
        echo "● $dir$file 설정 내용" >> $CREATE_FILE 2>&1
        cat $dir$file | grep -v "#" >> $CREATE_FILE 2>&1
        echo " " >> $CREATE_FILE 2>&1
       fi
      done
   done
echo " " >> $CREATE_FILE 2>&1

for dir in $HOMEDIRS
do
  for file in $FILES
  do
    if [ -f $dir$file ]
     then
       if [ `ls -al $dir$file | awk '{print $1}' | grep '.rw-------' | wc -l` -eq 1 ]
       then
         :
       else
         if [ `ls -al $dir$file | grep '\/dev\/null' | wc -l` -eq 1 ]
          then
           :
          else
           flag_2_12_2=0
         fi
       fi
     else
	   flag_2_12_2=0
     fi
  done
done
fi

echo "A@K@"										        >> $CREATE_FILE 2>&1
echo "@@@@"										        >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $flag_2_12_1 -eq 1 ]
  then
    echo "[2.12] 양호" >> $CREATE_FILE 2>&1
  else
    if [ $flag_2_12_2 -eq 1 ]
      then
        echo "[2.12] 양호" >> $CREATE_FILE 2>&1
      elseecho " "                                                                                       >> $CREATE_FILE 2>&1
        echo "[2.12] 취약" >> $CREATE_FILE 2>&1
	fi
fi

echo " "											>> $CREATE_FILE 2>&1
echo "U-28 END"                                                                                 >> $CREATE_FILE 2>&1
echo "#######################################################################################"  >> $CREATE_FILE 2>&1
echo "======================================================================================="  >> $CREATE_FILE 2>&1
echo "U-28 END"

echo " "                                                                                        >> $CREATE_FILE 2>&1
echo " "                                                                                        >> $CREATE_FILE 2>&1
echo " "




echo "U-29 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-29 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                               2.13 접속 IP 및 포트 제한                               " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/hosts.deny 에서 all deny 정책 확인 후 /etc/hosts.allow 에서 필요한 서비스만 오픈된 경우 양호">> $CREATE_FILE 2>&1
echo "■ 두 파일이 존재하지 않을 경우에도 취약에 해당"					       >> $CREATE_FILE 2>&1
echo "■ 현황"										       >> $CREATE_FILE 2>&1
echo " "										       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
flag_2_13=1

echo "① /etc/hosts.deny 내용"								       >> $CREATE_FILE 2>&1
echo " "										       >> $CREATE_FILE 2>&1
if [ -f /etc/hosts.deny ]
  then
    cat /etc/hosts.deny									       >> $CREATE_FILE 2>&1
	if [ -n `cat /etc/hosts.deny | grep -i '^ALL*:*ALL$' | grep -v "#"` ]
	  then
	    echo "＊ /etc/hosts.deny 파일에서 all deny 정책을 적용하지 않았습니다."	       >> $CREATE_FILE 2>&1
		flag_2_13=0
	  else
	    :
    fi
  else
    echo "＊ /etc/hosts.deny 파일이 존재하지 않습니다."					       >> $CREATE_FILE 2>&1
	flag_2_13=0
fi
echo " "										       >> $CREATE_FILE 2>&1

echo "② /etc/hosts.allow 내용"								       >> $CREATE_FILE 2>&1
echo " "										       >> $CREATE_FILE 2>&1

if [ -f /etc/hosts.allow ]
  then
	cat /etc/hosts.allow							>> $CREATE_FILE 2>&1
	if [ `cat /etc/hosts.allow | grep  -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' | grep -v "#" | wc -l` -eq 0 ]
		then
		echo "＊ /etc/hosts.allow 파일에서 서비스 허용 정책을 적용하지 않았습니다."	       >> $CREATE_FILE 2>&1
		flag_2_13=0
	fi  
else
echo "＊ /etc/hosts.allow 파일이 존재하지 않습니다."				       >> $CREATE_FILE 2>&1
	flag_2_13=0
fi 
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "										       >> $CREATE_FILE 2>&1
if [ $flag_2_13 -eq 1 ]
  then
    echo "[2.13] 수동점검"								       >> $CREATE_FILE 2>&1
  else
    echo "[2.13] 취약"									       >> $CREATE_FILE 2>&1
fi

echo " " 										        >> $CREATE_FILE 2>&1
echo " " 										        >> $CREATE_FILE 2>&1
echo "U-29 END"                                                                                 >> $CREATE_FILE 2>&1
echo "#######################################################################################"  >> $CREATE_FILE 2>&1
echo "======================================================================================="  >> $CREATE_FILE 2>&1
echo "U-29 END"
unset flag_2_13
echo " "                                                                                        >> $CREATE_FILE 2>&1
echo " "                                                                                        >> $CREATE_FILE 2>&1
echo " "




echo "U-30 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-30 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                      2.14 host.lpd 파일 소유자 및 권한 설정                           " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/host.lpd 파일의 소유자가 root 이고, 권한이 600 이면 양호"                   >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1

if [ -f /etc/host.lpd  ]
then
	ls -alL /etc/host.lpd                                                                  >> $CREATE_FILE 2>&1
else
	echo "＊/etc/host.lpd  파일이 없습니다."                                               >> $CREATE_FILE 2>&1
fi

echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "     										       >> $CREATE_FILE 2>&1

if [ -f /etc/host.lpd ]
then
  if [ `ls -alL /etc/host.lpd | egrep "root" | grep "...-------" | wc -l` -eq 1 ]	
    then
    echo "[2.14] 양호"							                       >> $CREATE_FILE 2>&1
    else
    echo "[2.14] 취약"							                       >> $CREATE_FILE 2>&1
  fi
else		
  echo "[2.14] 양호"								               >> $CREATE_FILE 2>&1
fi


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-30 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-30 END" 
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-31 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-31 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                                2.15 NIS 서비스 비활성화                               " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: NIS, NIS+ 서비스가 구동 중이지 않을 경우 양호"                                   >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"
if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
then
	echo "＊NIS, NIS+ Service Disable"                                                       		>> $CREATE_FILE 2>&1
	flag_2_15=1
else
	ps -ef | egrep $SERVICE | grep -v "grep"                                                    >> $CREATE_FILE 2>&1
	flag_2_15=0
fi
echo "A@K@"									       												>> $CREATE_FILE 2>&1
echo "@@@@"									      												>> $CREATE_FILE 2>&1
echo " "     										       >> $CREATE_FILE 2>&1
if [ $flag_2_15 -eq 1 ]
  then
    echo "[2.15] 양호"										>> $CREATE_FILE 2>&1
  else
    echo "[2.15] 취약"										>> $CREATE_FILE 2>&1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-31 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-31 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-32 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-32 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                                  2.16 UMASK 설정 관리                                 " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: UMASK 값이 022 이면 양호"                                                        >> $CREATE_FILE 2>&1
echo "■       : (1) sh, ksh, bash 쉘의 경우 /etc/profile 파일 설정을 적용받음"                 >> $CREATE_FILE 2>&1
echo "■       : (2) csh, tcsh 쉘의 경우 /etc/csh.cshrc 또는 /etc/csh.login 파일 설정을 적용받음" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
echo "① 현재 로그인 계정 UMASK"                                                               >> $CREATE_FILE 2>&1
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
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `umask` -ge 22 ]
 then
  echo "[2.16] 양호"									       >> $CREATE_FILE 2>&1
 else
  echo "[2.16] 취약" 									       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-32 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-32 END"                                                                                
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-33 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-33 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                          2.17 홈 디렉토리 소유자 및 권한 설정                         " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 홈 디렉터리의 소유자가 /etc/passwd 내에 등록된 홈 디렉터리 사용자와 일치하고,"   >> $CREATE_FILE 2>&1
echo "■       : 홈 디렉터리에 타사용자 쓰기권한이 없으면 양호"                                 >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
echo "＊사용자 홈 디렉터리"                                                                   >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
flag_2_17=1

# 나중에 다시 확인 
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | uniq`
         for dir in $HOMEDIRS
          do
            if [ -d $dir ]
               then
				ls -dal $dir | grep '\d.........' 			       								>> $CREATE_FILE 2>&1
	    fi
         done

         for dir in $HOMEDIRS
          do
               if [ -d $dir ]
               then
                if [ `ls -dal $dir | grep "\d.......-."|  awk '{print $1}'  | wc -l` -eq 0 ]
                then
                  flag_2_17=0
                fi
               fi
         done
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $flag_2_17 -eq 1 ]
 then
  echo "[2.17] 양호" 									       >> $CREATE_FILE 2>&1
 else
  echo "[2.17] 취약"									       >> $CREATE_FILE 2>&1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-33 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-33 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       




echo "U-34 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-34 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                    2.18 홈 디렉토리로 지정한 디렉토리의 존재 관리                     " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 홈 디렉터리가 존재하지 않는 계정이 발견되지 않으면 양호"                         >> $CREATE_FILE 2>&1
# 홈 디렉토리가 존재하지 않는 경우, 일반 사용자가 로그인을 하면 사용자의 현재 디렉터리가 /로 로그인 되므로 관리,보안상 문제가 발생됨.
# 예) 해당 계정으로 ftp 로그인 시 / 디렉터리로 접속하여 중요 정보가 노출될 수 있음.
# 나중에 다시 확인
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
echo "＊홈 디렉터리가 존재하지 않은 계정"                                                      >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | uniq`
for dir in $HOMEDIRS
do
	if [ ! -d $dir ]
	then
		awk -F: '$6=="'${dir}'" { print "＊ 계정명(홈디렉터리):"$1 "(" $6 ")" }' /etc/passwd        >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $TMP/2.18.txt
	fi
done
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -s $TMP/2.18.txt ]
then
echo "[2.18] 취약" 									       >> $CREATE_FILE 2>&1
else	
echo "[2.18] 양호"									       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-34 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-34 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-35 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-35 START" - longtime
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                      2.19 숨겨진 파일 및 디렉토리 검색 및 제거                        " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 디렉토리 내에 숨겨진 파일을 확인 및 검색 하여 , 불필요한 파일 존재 경우 삭제 했을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       										>> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
find /tmp -name ".*" -ls  > $TMP/2.19.txt                                                                
find /home -name ".*" -ls  >> $TMP/2.19.txt                                                                    
find /usr -name ".*" -ls   >> $TMP/2.19.txt                                                                    
find /var -name ".*" -ls   >> $TMP/2.19.txt


if [ -s $TMP/2.19.txt ]
then
	cat $TMP/2.19.txt | head -5																	   >> $CREATE_FILE 2>&1
    echo "...중략..."                                                                          >> $CREATE_FILE 2>&1
    cat $TMP/2.19.txt | tail -5																	   >> $CREATE_FILE 2>&1
else
	echo "디렉터리 숨김 파일이 발견되지 않았습니다."                           					>> $CREATE_FILE 2>&1
fi
echo "A@K@"										       										    >> $CREATE_FILE 2>&1
echo "@@@@"										       											>> $CREATE_FILE 2>&1
echo " "  										       											>> $CREATE_FILE 2>&1
if [ -s $TMP/2.19.txt ]
then
  echo "[2.19] 취약" 									       									>> $CREATE_FILE 2>&1
else
  echo "[2.19] 수동점검" 									       							   >> $CREATE_FILE 2>&1
fi


echo "U-35 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-35 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                               3. 서비스 관리                                          " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "U-36 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-36 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                             3.01 finger 서비스 비활성화                               " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준 : Finger 서비스가 비활성화 되어 있는 경우 양호"				       				>> $CREATE_FILE 2>&1
echo "■ 현황"										       										>> $CREATE_FILE 2>&1
echo " "										       											>> $CREATE_FILE 2>&1
echo "*************************************주의사항******************************************" >> $CREATE_FILE 2>&1
echo "서비스 실행 여부 판단을 특정 포트로 하는 경우 실제 사용 하는 포트와 다를 수 있습니다. "  >> $CREATE_FILE 2>&1
echo "ex) *.23 LISTEN 일 경우 Telnet을 사용하는 것으로 판단 하나 실제로 23번에 MySql DB를"     >> $CREATE_FILE 2>&1
echo "사용 할 수 도 있으므로 실제로 WellKnown 포트를 사용 하는지 확인 해야함"                  >> $CREATE_FILE 2>&1
echo "*************************************주의사항******************************************" >> $CREATE_FILE 2>&1
echo "!@#$"										       											>> $CREATE_FILE 2>&1
echo "K@A@"										       											>> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp"                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
flag_3_1=1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -eq 0 ]
	then
		echo "＊Finger Service Disable"                                                           >> $CREATE_FILE 2>&1
	else
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		echo "＊Finger Service Enable"                                                           >> $CREATE_FILE 2>&1
		flag_3_1=0
	fi
else
	if [ `netstat -na | grep ":79 " | grep -i "^tcp" | wc -l` -eq 0 ]
	then
	echo "＊Finger Service Disable"                                                           >> $CREATE_FILE 2>&1	else
		netstat -na | grep ":79 " | grep -i "^tcp"                                                 >> $CREATE_FILE 2>&1
		echo "＊Finger Service Enable"                                                           >> $CREATE_FILE 2>&1
		flag_3_1=0	fi
fi
fi

echo "A@K@"																					   >> $CREATE_FILE 2>&1
echo "@@@@"																					   >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $flag_3_1 -eq 1 ]
  then
    echo "[3.01] 양호"								       >> $CREATE_FILE 2>&1
  else
    echo "[3.01] 취약"								       >> $CREATE_FILE 2>&1
fi
		

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-36 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-36 END"
unset port
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       



echo "U-37 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-37 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                             3.02 Anonymous FTP 비활성화                               " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: Anonymous FTP (익명 ftp)를 비활성화 시켰을 경우 양호"                            >> $CREATE_FILE 2>&1
echo "■       : (1)ftpd를 사용할 경우: /etc/passwd 파일내 FTP 또는 anonymous 계정이 존재하지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■       : (2)proftpd를 사용할 경우: /etc/passwd 파일내 FTP 계정이 존재하지 않으면 양호"  >> $CREATE_FILE 2>&1
echo "■       : (3)vsftpd를 사용할 경우: vsftpd.conf 파일에서 anonymous_enable=NO 설정이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1


if [ $result_3_18 -eq 1 ]
then
    echo "* ftp 서비스 미사용 중 "							       >> $CREATE_FILE 2>&1
else

  result_3_02_1=1

  
  if [ `cat /etc/passwd | grep -v "^#" | grep -i "^ftp" | wc -l` -eq 1 ]
    then
	  echo "① /etc/passwd 에서 ftp 계정 확인"						       >> $CREATE_FILE 2>&1
      echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
      cat /etc/passwd | grep -v "^#" | grep -i "^ftp"					       >> $CREATE_FILE 2>&1
      echo " "										       >> $CREATE_FILE 2>&1
      result_3_02_1=0
    else
    :
  fi
  if [ `cat /etc/passwd | grep -v "^#" | grep -i "^anonymous" | wc -l` -eq 1 ]
    then
	  echo "① /etc/passwd 에서 ftp 계정 확인"						       >> $CREATE_FILE 2>&1
      echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
      cat /etc/passwd | grep -v "^#" | grep -i "^anonymous"					       >> $CREATE_FILE 2>&1
      echo " "										       >> $CREATE_FILE 2>&1
      result_3_02_1=0
    else
      :
  fi
  if [ $result_3_02_1 -eq 1 ]
    then
      echo "* ftp 관련 계정이 없습니다."							       >> $CREATE_FILE 2>&1
    else
      echo "* ftp 관련 계정이 존재합니다."						       >> $CREATE_FILE 2>&1
  fi
  echo " "										       >> $CREATE_FILE 2>&1
  
  flag_3_2_2=1
  
  if [ -f /etc/vsftpd/vsftpd.conf ]
    then
      echo "② /etc/vsftpd/vsftpd.conf 에서 Anonymous 접속 설정 확인" >> $CREATE_FILE 2>&1
	  echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	  echo " " >> $CREATE_FILE 2>&1
	  if [ `cat /etc/vsftpd/vsftpd.conf | grep -v "^#" | grep -i "anonymous_enabled=NO" | wc -l` -eq 1 ]
	    then
		  cat /etc/vsftpd/vsftpd.conf | grep -v "^#" | grep -i "anonymous_enabled*=*NO"  >> $CREATE_FILE 2>&1
		  result_3_02_2=0
	    else
	      :
	  fi
    else
      :
  fi
  echo " "										       >> $CREATE_FILE 2>&1
  
  
  if [ -f /etc/vsftpd.conf ]
    then
      echo "③ /etc/vsftpd.conf 에서 Anonymous 접속 설정 확인"				       >> $CREATE_FILE 2>&1
	  echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	  echo " " >> $CREATE_FILE 2>&1
	  if [ `cat /etc/vsftpd.conf | grep -v "^#" | grep -i "anonymous_enabled=NO" | wc -l` -eq 1 ]
	    then
		  cat /etc/vsftpd.conf | grep -v "^#" | grep -i "anonymous_enabled*=*NO">> $CREATE_FILE 2>&1
		  result_3_02_2=0
	    else
	      :
	  fi
    else
      :
  fi
fi


echo " "										       >> $CREATE_FILE 2>&1
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $flag_3_18 -eq 1 ]
  then
    echo "[3.02] 양호"									       >> $CREATE_FILE 2>&1
  else
    if [ $flag_3_2_1 -eq 0 ] || [ $flag_3_2_2 -eq 0 ]
      then
        echo "[3.02] 취약"								       >> $CREATE_FILE 2>&1
      else
        echo "[3.02] 양호"								       >> $CREATE_FILE 2>&1
    fi
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-37 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-37 END"                                                                                
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-38 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-38 START"  
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                             3.03 r 계열 서비스 비활성화                               " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: r-commands 서비스를 사용하지 않으면 양호"                                        >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "*************************************주의사항******************************************" >> $CREATE_FILE 2>&1
echo "서비스 실행 여부 판단을 특정 포트로 하는 경우 실제 사용 하는 포트와 다를 수 있습니다. "  >> $CREATE_FILE 2>&1
echo "ex) *.23 LISTEN 일 경우 Telnet을 사용하는 것으로 판단 하나 실제로 23번에 MySql DB를"     >> $CREATE_FILE 2>&1
echo "사용 할 수 도 있으므로 실제로 WellKnown 포트를 사용 하는지 확인 해야함"                  >> $CREATE_FILE 2>&1
echo "*************************************주의사항******************************************" >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
flag_3_3=1

echo "① 서비스 포트 활성화 여부 확인"                             >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		flag_3_3=0
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		flag_3_3=0
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		flag_3_3=0
	fi
fi

if [ $flag_3_3 -eq 1 ]
      then
        echo "＊r-commands Service Disable"                                                    	    >> $CREATE_FILE 2>&1
      else
        echo "＊r-commands Service Enable"                                                     	    >> $CREATE_FILE 2>&1
fi

echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $flag_3_3 -eq 1 ]
      then
        echo "[3.03] 양호"								       >> $CREATE_FILE 2>&1
      else
        echo "[3.03] 취약"								       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-38 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-38 END" 
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       






echo "U-39 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-39 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                          3.04 cron 파일 소유자 및 권한설정                            " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: cron.allow 또는 cron.deny 파일 권한이 640 미만이면 양호"                         >> $CREATE_FILE 2>&1
echo "■       : (cron.allow 또는 cron.deny 파일이 없는 경우 모든 사용자가 cron 명령을 사용할 수 있으므로 취약)" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"											>> $CREATE_FILE 2>&1
echo "K@A@"											>> $CREATE_FILE 2>&1
flag_3_4=1
echo "① /etc/cron.allow 파일 소유자 및 권한확인"					       >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1

if [ -f /etc/cron.allow ]
  then
    ls -al /etc/cron.allow							       >> $CREATE_FILE 2>&1
	echo " "									       >> $CREATE_FILE 2>&1
	
	if [ `ls -al /etc/cron.allow | awk '$3=="root"' | wc -l` -eq 0 ] # 소유자가 root인지 확인
	  then
	    echo "＊/etc/cron.allow 파일의 소유자가 root가 아닙니다. "		       >> $CREATE_FILE 2>&1
		echo " "										>> $CREATE_FILE 2>&1
		flag_3_4=0
	  else
	    :
	fi
	if [ `ls -al /etc/cron.allow | grep "^-..-.-----" | wc -l` -eq 0 ] # 파일 권한이 640 이하인지 확인
	  then
	    echo "＊/etc/cron.allow 파일의 권한이 640 이하가 아닙니다. "			>> $CREATE_FILE 2>&1
		echo " "								       >> $CREATE_FILE 2>&1
		flag_3_4=0
	  else
	    :
	fi
  else
    echo "＊/etc/cron.allow 파일이 없습니다. "					       >> $CREATE_FILE 2>&1
fi
echo " "										       >> $CREATE_FILE 2>&1

echo "② /etc/cron.deny 파일 소유자 및 권한확인"					       >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1

if [ -f /etc/cron.deny ]
  then
    ls -l /etc/cron.deny								       >> $CREATE_FILE 2>&1
	# 소유자가 root인지 확인
	if [ `ls -l /etc/cron.deny | awk '$3=="root"' | wc -l` -eq 0 ] 
	  then
	    echo "＊/etc/cron.deny 파일의 소유자가 root가 아닙니다. "		       >> $CREATE_FILE 2>&1
		echo " "								       >> $CREATE_FILE 2>&1
		flag_3_4=0
	  else
	    :
	fi
	# 파일 권한이 640 이하인지 확인
	if [ `ls -l /etc/cron.deny | grep "^-..-.-----" | wc -l` -eq 0 ] 
	  then
	    echo "＊/etc/cron.deny 파일의 권한이 640 이하가 아닙니다. "		       >> $CREATE_FILE 2>&1
		echo " "								       >> $CREATE_FILE 2>&1
		flag_3_4=0
	  else
	    :
	fi
  else
    echo "＊/etc/cron.deny 파일이 없습니다. "					        >> $CREATE_FILE 2>&1
fi

echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $flag_3_4 -eq 1 ]
  then
    echo "[3.04] 양호"										>> $CREATE_FILE 2>&1
  else
    echo "[3.04] 취약"										>> $CREATE_FILE 2>&1
fi
echo " "											>> $CREATE_FILE 2>&1


echo "U-39 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-39 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-40 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-40 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                        3.05 Dos 공격에취약한 서비스 비활성화                         " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: DoS 공격에취약한 echo , discard , daytime , chargen 서비스를 사용하지 않았을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"											>> $CREATE_FILE 2>&1
echo "K@A@"											>> $CREATE_FILE 2>&1
SERVICE_INETD="echo|discard|daytime|chargen"
flag_3_05=1

if [ -f /etc/inetd.conf ]
  then
    if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l ` -gt 0 ]
	  then
	    echo "① /etc/inetd.conf 확인" 										>> $CREATE_FILE 2>&1
		echo "-------------------------------------------------------------">> $CREATE_FILE 2>&1
		cat /etc/inetd.conf | grep -v '^#' | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
		flag_3_05=0
	  else
	    echo "＊DoS 공격에 취약한 서비스가 구동중이지 않습니다." >> $CREATE_FILE 2>&1
	fi
  else
    if [ `ls -alL /etc/xinetd.d/ | egrep $SERVICE_INETD | wc -l` -gt 0 ]
	  then
	    echo "② /etc/xinetd.d 확인" 										>> $CREATE_FILE 2>&1
		echo "-------------------------------------------------------------">> $CREATE_FILE 2>&1
		ls -alL /etc/xinetd.d/ | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
		flag_3_05=0
	  else
	    echo "＊DoS 공격에 취약한 서비스가 구동중이지 않습니다." >> $CREATE_FILE 2>&1
	fi
fi
echo "A@K@"											>> $CREATE_FILE 2>&1
echo "@@@@"											>> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $flag_3_05 -eq 1 ]
	then
		echo "[3.05] 양호"								>> $CREATE_FILE 2>&1
	else
		echo "[3.05] 취약"								>> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-40 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-40 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " " 




echo "U-41 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-41 START" 
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                              3.06 NFS 서비스 비활성화                                 " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 불필요한 NFS 서비스 관련 데몬이 제거되어 있는 경우 양호"                         >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"											>> $CREATE_FILE 2>&1
echo "K@A@"											>> $CREATE_FILE 2>&1


flag_3_06=1

echo "① NFS Server Daemon(nfsd)확인"                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ] 
 then
   ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"                >> $CREATE_FILE 2>&1
   flag_3_06=0
 else
   echo "* NFS Service 미사용 중입니다."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "A@K@"										        >> $CREATE_FILE 2>&1
echo "@@@@"											>> $CREATE_FILE 2>&1
echo " "                                                                                        >> $CREATE_FILE 2>&1


if [ $flag_3_06 -eq 1 ]
then
	echo "[3.06] 양호"								       										>> $CREATE_FILE 2>&1
else
	echo "[3.06] 취약"								       										>> $CREATE_FILE 2>&1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-41 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-41 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-42 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-42 START" 
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                                  3.07 NFS 접근 통제                                   " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준1: NFS 서버 데몬이 동작하지 않으면 양호"                                           >> $CREATE_FILE 2>&1
echo "■ 기준2: /etc/exports 파일 설정 확인 "													>> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"											>> $CREATE_FILE 2>&1
echo "K@A@"											>> $CREATE_FILE 2>&1


flag_3_07=1


if [ $flag_3_06 -eq 1 ]
then
  echo "＊ NFS Service Disable"                                                               >> $CREATE_FILE 2>&1
else
  echo "/etc/exports 파일 설정"                                                          >> $CREATE_FILE 2>&1
  echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
  if [ -f /etc/exports ]
    then
	  if [ `cat /etc/exports | grep -v "^#" | grep -v "^ *$" | grep "everyone" | wc -l` -gt 0 ]
	  then
		  cat /etc/exports | grep -v "^#" | grep -v "^ *$" | grep "everyone"                           >> $CREATE_FILE 2>&1
		  
	  else
		  echo "설정 내용이 없습니다."                                                               >> $CREATE_FILE 2>&1
		  flag_3_07=0
	  fi
  else
    echo "/etc/exports 파일이 없습니다."                                                         >> $CREATE_FILE 2>&1
    flag_3_07=0
  fi
fi


echo "A@K@"											>> $CREATE_FILE 2>&1
echo "@@@@"											>> $CREATE_FILE 2>&1
echo " "                                                                                        >> $CREATE_FILE 2>&1

if [ $flag_3_06 -eq 1 ]
	then
	echo "[3.07] 양호"								>> $CREATE_FILE 2>&1
else
	if [ $flag_3_07 -eq 1 ]
	then
		echo "[3.07] 수동점검"						>> $CREATE_FILE 2>&1
	else
		echo "[3.07] 취약"								>> $CREATE_FILE 2>&1
	fi

fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-42 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-42 END" 
unset flag_3_15
unset flag_3_07
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-43 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-43 START"    
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                                 3.08 automountd 제거                                  " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: automountd 서비스가 동작하지 않을 경우 양호"                                     >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"											>> $CREATE_FILE 2>&1
echo "K@A@"											>> $CREATE_FILE 2>&1
echo "Automountd Daemon 확인"                                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep 'automount|autofs' | grep -v "grep" | egrep -v "statdaemon|emi" | wc -l` -gt 0 ] 
then
	ps -ef | egrep 'automount|autofs' | grep -v "grep" | egrep -v "statdaemon|emi"              >> $CREATE_FILE 2>&1
	flag_3_08=0
else
	echo "＊Automountd Daemon Disable"                                                         >> $CREATE_FILE 2>&1
	flag_3_08=1
fi

echo "A@K@"											>> $CREATE_FILE 2>&1
echo "@@@@"											>> $CREATE_FILE 2>&1
echo " "                                                                                        >> $CREATE_FILE 2>&1

if [ $flag_3_08 -eq 1 ]
	then
		echo "[3.08] 양호"								>> $CREATE_FILE 2>&1
	else
		echo "[3.08] 취약"								>> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-43 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-43 END"     
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-44 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-44 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                                 3.09 RPC 서비스 확인                                  " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준 : 불필요한 RPC 서비스가 비활성화 되어 있는 경우 양호" >> $CREATE_FILE 2>&1
echo "(rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd)" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"											>> $CREATE_FILE 2>&1
echo "K@A@"											>> $CREATE_FILE 2>&1
SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd"
flag_3_09=1
echo " 서비스 포트 활성화 여부 확인"  >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
if [ -f /etc/inetd.conf ]
  then
    if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l` -gt 0 ]
	then
        echo "＊불필요한 RPC 서비스가 구동중입니다." 										>> $CREATE_FILE 2>&1
		cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD 						>> $CREATE_FILE 2>&1
        flag_3_09=0
	else
	    echo "＊불필요한 RPC 서비스가 비활성화 되어있습니다.." 								>> $CREATE_FILE 2>&1
	fi
else
    echo "/etc/inetd.conf 파일이 존재하지 않습니다."                  						>> $CREATE_FILE 2>&1
fi
echo "------------------------------------------------------------------------------" 		>> $CREATE_FILE 2>&1
if [ -f /etc/xinetd.conf ]
  then
  if [ `chkconfig --list |grep -i "^[^a-z]$SERVICE_INETD" | wc -l` -gt 0 ]
	then
		echo "＊불필요한 RPC 서비스가 구동중입니다." 											>> $CREATE_FILE 2>&1
		chkconfig --list | grep -i "^[^a-z]*$SERVICE_INETD"  									>> $CREATE_FILE 2>&1
		flag_3_09=0
  else
	echo "＊불필요한 RPC 서비스가 비활성화 되어있습니다.." 									>> $CREATE_FILE 2>&1
  fi
else
    echo "/etc/xinetd.conf 파일이 존재하지 않습니다."                  						>> $CREATE_FILE 2>&1
fi

echo "A@K@"																					>> $CREATE_FILE 2>&1
echo "@@@@"																						>> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $flag_3_09 -eq 1 ]
	then
		echo "[3.09] 양호"								>> $CREATE_FILE 2>&1
	else
		echo "[3.09] 취약"								>> $CREATE_FILE 2>&1
fi



echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-44 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-44 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-45 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-45 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                                 3.10 NIS , NIS+ 점검                                  " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: NIS, NIS+ 서비스가 구동 중이지 않을 경우 양호"                                 >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"											>> $CREATE_FILE 2>&1
echo "K@A@"											>> $CREATE_FILE 2>&1
if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
then
	echo "＊NIS, NIS+ Service Disable"                                                       		>> $CREATE_FILE 2>&1
	flag_3_10=1
else
	ps -ef | egrep $SERVICE | grep -v "grep"                                                    >> $CREATE_FILE 2>&1
	flag_3_10=0
fi
echo "A@K@"									       												>> $CREATE_FILE 2>&1
echo "@@@@"									      												>> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $flag_3_10 -eq 1 ]
  then
    echo "[3.10] 양호"										>> $CREATE_FILE 2>&1
  else
    echo "[3.10] 취약"										>> $CREATE_FILE 2>&1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-45 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-45 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-46 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-46 START"  
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                            3.11 tftp, talk 서비스 비활성화                            " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: tftp, talk, ntalk 서비스가 구동 중이지 않을 경우 양호"                         >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"											>> $CREATE_FILE 2>&1
echo "K@A@"											>> $CREATE_FILE 2>&1
echo "tftp, talk, ntalk 서비스 구동 확인"							>> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep "tftp|talk" | grep -v "grep" | wc -l` -eq 0 ]
  then
    echo "＊tftp, talk Service Disable"                                                       		>> $CREATE_FILE 2>&1
	flag_3_11=1
  else
    ps -ef | egrep "tftp|talk" | grep -v "grep" >> $CREATE_FILE 2>&1
	flag_3_11=0
fi
echo "A@K@"									       												>> $CREATE_FILE 2>&1
echo "@@@@"									      												>> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $flag_3_11 -eq 1 ]
  then
    echo "[3.11] 양호"										>> $CREATE_FILE 2>&1
  else
    echo "[3.11] 취약"										>> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-46 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-46 END" 
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-47 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-47 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                               3.12 Sendmail 버전 점검                                 " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: sendmail 버전이 8.15.2 이상이면 양호"                                            >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"											>> $CREATE_FILE 2>&1
echo "K@A@"											>> $CREATE_FILE 2>&1
flag_3_12_1=1
flag_3_12_2=1

echo "① Sendmail 프로세스 확인"									>> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
 then
  echo "＊Sendmail Service Disable"							>> $CREATE_FILE 2>&1
 else
  ps -ef | grep sendmail | grep -v "grep"						>> $CREATE_FILE 2>&1
  flag_3_12_1=0
fi
echo " " >> $CREATE_FILE 2>&1

echo "② sendmail 버전 확인" >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1

if [ -f /etc/mail/sendmail.cf ]
   then
     grep -v '^ *#' /etc/mail/sendmail.cf | grep DZ >> $CREATE_FILE 2>&1
	 # 버전이 8.15.2 이상인지 확인하는 구문
	 if [ `grep -v '^ *#' /etc/mail/sendmail.cf | grep DZ | awk -F"Z" '{print $2}' | awk -F"." '($1 > 8) || ($1 >= 8 && $2 > 15) || ($1 >= 8 && $2 >= 15 && $3 >= 2)'  | wc -l` -eq 1 ] 
       then
         echo "＊Sendmail 버전이 8.15.2 이상입니다."						>> $CREATE_FILE 2>&1
       else
         echo "＊Sendmail 버전이 8.15.2 이상이 아닙니다."					>> $CREATE_FILE 2>&1
		 flag_3_12_2=0
     fi
   else
     echo "＊/etc/mail/sendmail.cf 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo "A@K@"											>> $CREATE_FILE 2>&1
echo "@@@@"										        >> $CREATE_FILE 2>&1

echo " "											>> $CREATE_FILE 2>&1
if [ $flag_3_12_1 -eq 1 ] || [ $flag_3_12_2 -eq 1 ]
  then
    echo "[3.12] 양호"										>> $CREATE_FILE 2>&1
  else
    echo "[3.12] 취약"										>> $CREATE_FILE 2>&1
fi


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-47 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-47 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " " 



echo "U-48 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-48 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                              3.13 스팸 메일 릴레이 제한                               " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준 : SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있는 경우 양호"		>> $CREATE_FILE 2>&1
echo "■ /etc/mail/access 파일이 존재하지 않을 경우에도 취약으로 간주"				>> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"											>> $CREATE_FILE 2>&1
echo "K@A@"											>> $CREATE_FILE 2>&1
flag_3_13=1

if [ $flag_3_12_1 -eq 1 ]
  then
    echo "＊Sendmail Service Disable"							>> $CREATE_FILE 2>&1
else
	echo "/etc/mail/sendmail.cf 파일 옵션 확인"									>> $CREATE_FILE 2>&1
    echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	if [ -f /etc/mail/sendmail.cf ]
	  then
		if [ `cat /etc/mail/sendmail.cf | grep -v "^#"| grep "R$\*" | grep "Relaying denied" | wc -l` -eq 0 ]
		  then
			echo "＊SMTP 릴레이 제한이 되어 있지 않습니다."				>> $CREATE_FILE 2>&1
			flag_3_13=0
		  else
			cat /etc/mail/sendmail.cf | grep "R$\*" | grep "Relaying denied"		>> $CREATE_FILE 2>&1
		fi
		echo " "									>> $CREATE_FILE 2>&1
	else
	    echo "＊/etc/mail/sendmail.cf 파일이 존재하지 않습니다."				>> $CREATE_FILE 2>&1
		flag_3_13=0
	fi
fi
echo "A@K@"											>> $CREATE_FILE 2>&1
echo "@@@@"										        >> $CREATE_FILE 2>&1
echo " " 											>> $CREATE_FILE 2>&1

if [ $flag_3_12_1 -eq 1 ] || [ $flag_3_13 -eq 1 ]
  then
    echo "[3.13] 양호"										>> $CREATE_FILE 2>&1
  else
    echo "[3.13] 취약"										>> $CREATE_FILE 2>&1
fi



echo " " 											>> $CREATE_FILE 2>&1
echo "U-48 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-48 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-49 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-49 START" 
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                         3.14 일반사용자의 Sendmail 실행 방지                          " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있을 경우 양호"             >> $CREATE_FILE 2>&1
echo "■       : (restrictqrun 옵션이 설정되어 있을 경우 양호)"                                 >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"											>> $CREATE_FILE 2>&1
echo "K@A@"											>> $CREATE_FILE 2>&1
flag_3_14=1

if [ $flag_3_12_1 -eq 1 ]
  then
    echo "＊Sendmail Service Disable"							>> $CREATE_FILE 2>&1
else
  echo "/etc/mail/sendmail.cf 파일 옵션 확인"									>> $CREATE_FILE 2>&1
  echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
  if [ -f /etc/mail/sendmail.cf ]
    then
      if [ `cat /etc/mail/sendmail.cf | grep -i "O PrivacyOptions" | grep -i "restrictqrun" | grep -v "#" | wc -l ` -eq 0 ]
	    then
	    echo "＊Sendmail 실행 방지가 설정되어 있지 않습니다."				>> $CREATE_FILE 2>&1
		flag_3_14=0
	  else
	    cat /etc/mail/sendmail.cf | grep -i "O PrivacyOptions"					>> $CREATE_FILE 2>&1
	  fi
  else
    echo "＊/etc/mail/sendmail.cf 파일이 존재하지 않습니다."					>> $CREATE_FILE 2>&1
	flag_3_14=0
  fi
fi
echo "A@K@"											>> $CREATE_FILE 2>&1
echo "@@@@"										        >> $CREATE_FILE 2>&1
echo " " 											>> $CREATE_FILE 2>&1

if [ $flag_3_12_1 -eq 1 ] || [ $flag_3_14 -eq 1 ]
  then
    echo "[3.14] 양호"										>> $CREATE_FILE 2>&1
  else
    echo "[3.14] 취약"										>> $CREATE_FILE 2>&1
fi


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-49 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-49 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-50 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-50 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                               3.15 DNS 보안 버전 패치                                 " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: DNS 서비스를 사용하지 않거나,양호한 버전을 사용하고 있을 경우 양호"           >> $CREATE_FILE 2>&1
echo "■       : (양호한 버전: 8.4.6, 8.4.7, 9.2.8-P1, 9.3.4-P1, 9.4.1-P1, 9.5.0a6)"            >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
# DNS 서비스 실행 여부 확인
flag_3_15=0
if [ `ps -ef | grep named | grep -v grep | wc -l` -eq 0 ]
then
echo "＊DNS Service Disable"							>> $CREATE_FILE 2>&1
flag_3_15=1
else
if [ `named -v | wc -l` -eq 1 ]
  then
    echo "BIND 버전 확인"                                                                    >> $CREATE_FILE 2>&1
    echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
    named -v | grep BIND                                                                      >> $CREATE_FILE 2>&1
    else
    echo "BIND 파일이 없습니다."                                                             >> $CREATE_FILE 2>&1
fi
fi
echo "A@K@"											>> $CREATE_FILE 2>&1
echo "@@@@"											>> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $flag_3_15 -eq 1 ]
  then
    echo "[3.15] 양호"										>> $CREATE_FILE 2>&1
  else
    if [ `named -v | egrep "8.4.6|8.4.7|9.2.8-P1|9.3.4-P1|9.4.1-P1|9.5.0a6|9.6.|9.8.[4-9]|9.9.[2-9]" | wc -l` -gt 0 ]
  then
    echo "[3.15] 양호"										>> $CREATE_FILE 2>&1
  else
    echo "[3.15] 수동점검"										>> $CREATE_FILE 2>&1
fi
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-50 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-50 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-51 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-51 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                             3.16 DNS Zone Transfer 설정                               " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: DNS 서비스를 사용하지 않거나 Zone Transfer 가 제한되어 있을 경우 양호"           >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1

if [ $flag_3_15 -eq 1 ]
  then
  echo "＊DNS Service Disable"							>> $CREATE_FILE 2>&1
else
  echo "/etc/named.conf 파일의 allow-transfer 확인"                                            >> $CREATE_FILE 2>&1
  echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
  if [ -f /etc/named.conf ]
    then
	cat /etc/named.conf | grep 'allow-transfer'                                            >> $CREATE_FILE 2>&1
  else
	echo "/etc/named.conf 파일이 없습니다."                                                >> $CREATE_FILE 2>&1
  fi
  echo " "                                                                                       >> $CREATE_FILE 2>&1
  echo "/etc/named.boot 파일의 xfrnets 확인"                                                   >> $CREATE_FILE 2>&1
  echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
  if [ -f /etc/named.boot ]
    then
	cat /etc/named.boot | grep "\xfrnets"                                                        >> $CREATE_FILE 2>&1
  else
	echo "/etc/named.boot 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
  fi
fi
echo "A@K@"											>> $CREATE_FILE 2>&1
echo "@@@@"											>> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $flag_3_15 -eq 1 ]
  then
     echo "[3.16] 양호"										>> $CREATE_FILE 2>&1
  else
     if [ -f /etc/named.conf ]
       then
         if [ `cat /etc/named.conf | grep "\allow-transfer.*[0-256].[0-256].[0-256].[0-256].*" | grep -v "#" | wc -l` -eq 0 ]
            then
               echo "[3.16] 취약" 								>> $CREATE_FILE 2>&1
            else
               echo "[3.16] 양호" 								>> $CREATE_FILE 2>&1
          fi
        else
          if [ -f /etc/named.boot ]
           then
             if [ `cat /etc/named.boot | grep "\xfrnets.*[0-256].[0-256].[0-256].[0-256].*" | grep -v "#" | wc -l` -eq 0 ]
            then
               echo "[3.16] 취약" 								>> $CREATE_FILE 2>&1
            else
               echo "[3.16] 양호" 								>> $CREATE_FILE 2>&1
            fi
           else
              echo "[3.16] 수동점검" 								>> $CREATE_FILE 2>&1
          fi

     fi
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-51 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-51 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-52 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-52 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                                3.17 ssh 원격접속 허용                                 " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준 : 원격 접속 시 SSH 프로토콜을 사용하는 경우 양호"				       >> $CREATE_FILE 2>&1
echo "■ 현황"										       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
echo " "										       >> $CREATE_FILE 2>&1
echo "① ssh 서비스 사용여부 확인"							       >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo "** netstat -tnlp 명령어를 활용한 ssh 포트 확인(일치하는지 확인)"					       >> $CREATE_FILE 2>&1
netstat -tnlp | grep -v 127.0.0.1 | sed 's/:::/0 /g' | sed 's/[:\/]/ /g' | awk '{print $5"\t"$10}' | sort -ug | grep sshd >> $CREATE_FILE 2>&1
echo " "                                                                                        >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo " ＊SSH Service Disable"                                                  >> $CREATE_FILE 2>&1
		flag_3_17=0
	else
		ps -ef | grep sshd | grep -v "grep"                                            >> $CREATE_FILE 2>&1
		flag_3_17=1
fi
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"								                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $flag_3_17 -eq 1 ]
  then
    echo "[3.17] 양호"								               >> $CREATE_FILE 2>&1
  else
    echo "[3.17] 취약"								               >> $CREATE_FILE 2>&1
fi

echo "U-52 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-52 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       




echo "U-53 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-53 START" 
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                                 3.18 ftp 서비스 확인                                  " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: ftp 서비스가 비활성화 되어 있을 경우 양호"                                       >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "*************************************주의사항******************************************" >> $CREATE_FILE 2>&1
echo "서비스 실행 여부 판단을 특정 포트로 하는 경우 실제 사용 하는 포트와 다를 수 있습니다. "  >> $CREATE_FILE 2>&1
echo "ex) *.23 LISTEN 일 경우 Telnet을 사용하는 것으로 판단 하나 실제로 23번에 MySql DB를"     >> $CREATE_FILE 2>&1
echo "사용 할 수 도 있으므로 실제로 WellKnown 포트를 사용 하는지 확인 해야함"                  >> $CREATE_FILE 2>&1
echo "*************************************주의사항******************************************" >> $CREATE_FILE 2>&1
flag_3_18=1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                  	>> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"           >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
then
	cat /etc/services | awk -F" " '$1=="ftp" {print "" $1 " " $2}' | grep "tcp"	                >> $CREATE_FILE 2>&1
else
	echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)"                                 >> $CREATE_FILE 2>&1
fi
echo " "																						>> $CREATE_FILE 2>&1

if [ `ps -ef | grep "vsftpd" | grep -v "grep" | awk '{print $9}' | grep "/" | uniq | wc -l` -gt 0 ]
then
    APROC1=`ps -ef | grep "vsftpd" | grep -v "grep" | awk '{print $9}' | grep "/" | uniq`
    vsfile=`echo $APROC1 | awk '{print $1}'`

if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
    then
        cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' >> $CREATE_FILE 2>&1
    else
        echo "(2)VsFTP 포트: 포트 설정 X (Default 21번 포트 사용중)"                             >> $CREATE_FILE 2>&1
fi
    else
    echo "(2)VsFTP 포트: VsFTP가 설치되어 있지 않습니다."                                        >> $CREATE_FILE 2>&1
fi

echo " "																						>> $CREATE_FILE 2>&1
if [ `ps -ef | grep "proftpd" | grep -v "grep" | awk '{print $8}' | uniq | wc -l` -gt 0 ]
then
    if [ `proftpd -V | grep -i "proftpd.conf" | wc -l` -gt 0 ]	
	then
	profile=`proftpd -V | grep -i "proftpd.conf" | awk '{print $1}'`
	fi

	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}'    >> $CREATE_FILE 2>&1
	else
		echo "(3)ProFTP 포트: 포트 설정 X (/etc/service 파일에 설정된 포트를 사용중)"              >> $CREATE_FILE 2>&1
	fi
else
	echo "(3)ProFTP 포트: ProFTP가 설치되어 있지 않습니다."                                      >> $CREATE_FILE 2>&1
fi

echo " "																						>> $CREATE_FILE 2>&1


echo "②-② 서비스 포트 활성화 여부 확인"                                                      >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
################# /etc/services 파일에서 포트 확인 #################
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "LISTEN" | head -1               				>> $CREATE_FILE 2>&1
		flag_3_18=0
		
	fi
else
	netstat -na | grep ":21 " | grep -i "LISTEN" | head -1                              		>> $CREATE_FILE 2>&1
fi
################# vsftpd 에서 포트 확인 ############################
if [ `ps -ef | grep "vsftpd" | grep -v "grep" | awk '{print $9}' | grep "/" | uniq | wc -l` -gt 0 ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}' | wc -l` -eq 0 ]
	then
		port=21
	else
		port=`cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}'`
	fi
	if [ `netstat -na | grep ":$port " | grep -i "LISTEN" | head -1 |  wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "LISTEN" | head -1 |							>> $CREATE_FILE 2>&1
		flag_3_18=0

	fi
fi
################# proftpd 에서 포트 확인 ###########################
if [ `ps -ef | grep "proftpd" | grep -v "grep" | awk '{print $8}' | uniq | wc -l` -gt 0 ]
then
	port=`cat $profile | grep "Port" | grep -v "^#" | awk '{print $2}'`
	if [ `netstat -na | grep ":$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "LISTEN" | head -1 							  >> $CREATE_FILE 2>&1
		flag_3_18=0
	fi
fi

echo "A@K@"										       											>> $CREATE_FILE 2>&1
echo "@@@@"										       											>> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $flag_3_18 -eq 1 ]
  then
    echo "[3.18] 양호"									       									>> $CREATE_FILE 2>&1
  else
    echo "[3.18] 취약"									       									>> $CREATE_FILE 2>&1
fi


echo " "										       											>> $CREATE_FILE 2>&1
echo "U-53 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-53 END" 
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-54 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-54 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                               3.19 ftp 계정 shell 제한                                " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: ftp 서비스가 비활성화 되어 있을 경우 양호"                                       >> $CREATE_FILE 2>&1
echo "■       : ftp 서비스 사용 시 ftp 계정의 Shell을 접속하지 못하도록 설정하였을 경우 양호"  >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       										   >> $CREATE_FILE 2>&1
echo "K@A@"										       										   >> $CREATE_FILE 2>&1



if [ $flag_3_18 -eq 1 ]
then
  echo "*ftp 서비스 미사용 중입니다."															>> $CREATE_FILE 2>&1
else
  echo "① ftp 계정확인 "									       								>> $CREATE_FILE 2>&1
  echo "------------------------------------------------------------------------------"         >> $CREATE_FILE 2>&1
  cat /etc/passwd | grep -v "^#" | grep "ftp" 													>> $CREATE_FILE 2>&1
  if [ `cat /etc/passwd | grep -v "^#" | grep "ftp" | wc -l` -eq 0 ]; then
    echo "＊ /etc/passwd 파일에 ftp 관련 계정이 존재하지 않습니다."			       				>> $CREATE_FILE 2>&1
  fi
fi




echo "A@K@"										       											>> $CREATE_FILE 2>&1
echo "@@@@"										       											>> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $flag_3_18 -eq 1 ]
  then
    echo "[3.19] 양호"									       									>> $CREATE_FILE 2>&1
    echo "* ftp 서비스 미사용 중입니다."   						       							>> $CREATE_FILE 2>&1
  else
    if [ `cat /etc/passwd | awk -F: '$1=="ftp"' | wc -l` -gt 0 ]
	then
	  if [ `cat /etc/passwd | grep -v "^#" | grep "ftp" | awk -F: '$7=="/bin/false" || $7=="/sbin/nologin"' | wc -l` -eq 0 ]
        then
          echo "[3.19] 취약"								       									>> $CREATE_FILE 2>&1
        else
          echo "[3.19] 양호"								       									>> $CREATE_FILE 2>&1
      fi
	 else
	   echo "[3.19] 양호"								       									>> $CREATE_FILE 2>&1
	fi
fi


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-54 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-54 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       




echo "U-55 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-55 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                        3.20 Ftpusers 파일 소유자 및 권한 설정                         " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: ftpusers 파일의 소유자가 root이고, 권한이 640 미만이면 양호"                     >> $CREATE_FILE 2>&1
echo "■       : [FTP 종류별 적용되는 파일]"                                                    >> $CREATE_FILE 2>&1
echo "■       : (1)ftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers"                                >> $CREATE_FILE 2>&1
echo "■       : (2)proftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers"                             >> $CREATE_FILE 2>&1
echo "■       : (3)vsftpd: /etc/vsftpd/ftpusers, /etc/vsftpd/user_list (또는 /etc/vsftpd.ftpusers, /etc/vsftpd.user_list)" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1

if [ $flag_3_18 -eq 1 ]
then
  echo "* ftp 서비스 미사용 중입니다."   						       							>> $CREATE_FILE 2>&1
else

  flag_3_20=1
  pwd_ftpusers="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list /etc/vsftpd.ftpusers /etc/vsftpd.user_list"
  for ftpuser in $pwd_ftpusers;do
	  if [ -f $ftpuser ]
	    then
		  ls -al $ftpuser >> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1
		  echo "① Ftpusers 소유자 확인 "									       						  >> $CREATE_FILE 2>&1
	      echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
		  if [ `ls -al $ftpuser | awk '$3!="root"' | wc -l` -eq 1 ]
		    then
			  ls -al $ftpuser | awk '$3!="root"' >> $CREATE_FILE 2>&1
			  echo "＊ $ftpuser 파일의 소유자가 root가 아닙니다." >> $CREATE_FILE 2>&1
			  flag_3_20=0
		    else
			  echo "＊ $ftpuser 파일의 소유자가 root 입니다." >> $CREATE_FILE 2>&1
		  fi
		  echo " " >> $CREATE_FILE 2>&1
		
		  echo "① Ftpusers 권한 확인 "									       						  >> $CREATE_FILE 2>&1
	      echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
		  if [ `ls -al $ftpuser | grep "^-..-.-----" | wc -l` -eq 0 ]
		    then
			  ls -al $ftpuser | grep "^-..-.-----"  >> $CREATE_FILE 2>&1
			  echo "＊ $ftpuser 파일의 권한이 640을 초과합니다." >> $CREATE_FILE 2>&1
			  flag_3_20=0
		    else
			  echo "＊ $ftpuser 파일의 권한이 640 이하입니다." >> $CREATE_FILE 2>&1
		  fi
		  echo " "									>> $CREATE_FILE 2>&1
	    else
		  echo "＊ $ftpuser 파일이 존재하지 않습니다.." >> $CREATE_FILE 2>&1
	  fi
  done
fi


echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "										       >> $CREATE_FILE 2>&1
# 3.18번 서비스 사용여부 결과값을 항목에서 가져다 씀
# ftp가 비활성화 되어 있을 경우 /etc/passwd 파일 관련 계정 존재해도 양호
if [ $flag_3_18 -eq 1 ]
  then
    echo "[3.20] 양호"									       >> $CREATE_FILE 2>&1
  else
    if [ $flag_3_20 -eq 1 ]
      then
        echo "[3.20] 양호"								       >> $CREATE_FILE 2>&1
      else
        echo "[3.20] 취약"								       >> $CREATE_FILE 2>&1
    fi
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-55 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-55 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       




echo "U-56 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-56 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                                3.21 Ftpusers 파일 설정                                " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: ftp 를 사용하지 않거나, ftp 사용시 ftpusers 파일에 root가 있을 경우 양호"        >> $CREATE_FILE 2>&1
echo "■       : [FTP 종류별 적용되는 파일]"                                                    >> $CREATE_FILE 2>&1
echo "■       : (1)ftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers - root 확인"                    >> $CREATE_FILE 2>&1
echo "■       : (2)proftpd: /etc/proftpd.con - RootLogin on/off 확인"                          >> $CREATE_FILE 2>&1
echo "■       : (3)vsftpd: /etc/vsftpd/ftpusers, /etc/vsftpd/user_list (또는 /etc/vsftpd.ftpusers, /etc/vsftpd.user_list)" >> $CREATE_FILE 2>&1
echo "■       : - root 확인"                          										   >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1


if [ $flag_3_18 -eq 1 ]
then
  echo "* ftp 서비스 미사용 중입니다."   						       							>> $CREATE_FILE 2>&1
else
  flag_3_21=1


  echo "① ftpusers 파일 설정 확인"                                                               >> $CREATE_FILE 2>&1
  echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1

  for file in $pwd_ftpusers=;do
	  if [ -f $file ]
	  then											>> $CREATE_FILE 2>&1
	    if [ `cat $file | grep "root" | grep -v "^#" | wc -l` -gt 0 ]
	    then
	      echo "＊ $file 파일내용: root 계정이 등록되어 있음."					>> $CREATE_FILE 2>&1
	    
	    else
          echo "＊ $file 파일내용: root 계정이 등록되어 있지 않음."                            >> $CREATE_FILE 2>&1
	    fi
	  else 
	    echo "$file 파일이 존재하지 않습니다."					       >> $CREATE_FILE 2>&1
	  fi
  done

  echo " "                                                                                       >> $CREATE_FILE 2>&1
  echo "② proftpd 파일 설정 확인"                                                               >> $CREATE_FILE 2>&1
  echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
  if [ -f /etc/proftpd.conf ]
     then
       cat /etc/proftpd.conf | grep -i "RootLogin"											  >> $CREATE_FILE 2>&1
  else
      echo "proftpd.conf 파일이 존재하지 않습니다."											  >> $CREATE_FILE 2>&1
  fi
fi


echo "A@K@"									               >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

# 3.18번 서비스 사용여부 결과값을 항목에서 가져다 씀
# ftp가 비활성화 되어 있을 경우 /etc/passwd 파일 관련 계정 존재해도 양호
if [ $flag_3_18 -eq 1 ]
  then
    echo "[3.21] 양호"									       >> $CREATE_FILE 2>&1
  else
    if [ $flag_3_21 -eq 1 ] 
      then
        echo "[3.21] 수동점검"								       >> $CREATE_FILE 2>&1
      else
        echo "[3.21] 수동점검"								       >> $CREATE_FILE 2>&1
    fi
fi


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-56 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-56 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-57 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-57 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                            3.22 at 파일 소유자 및 권한설정                            " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: at.allow 또는 at.deny 파일 권한이 640 미만이면 양호"                             >> $CREATE_FILE 2>&1
echo "■       : (at.allow 또는 at.deny 파일이 없는 경우 모든 사용자가 at 명령을 사용할 수 있으므로 취약)" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"											>> $CREATE_FILE 2>&1
echo "K@A@"											>> $CREATE_FILE 2>&1

flag_3_22=1

echo "① /etc/at.allow 파일확인"								>> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/at.allow ]
  then
    ls -al /etc/at.allow									>> $CREATE_FILE 2>&1
	if [ `ls -al /etc/at.allow | awk '$3 != "root"' | wc -l` -eq 1 ]
	  then
	    echo "＊/etc/at.allow 파일의 소유자가 root가 아닙니다."			>> $CREATE_FILE 2>&1
		flag_3_22=0
	  else
	    echo "＊/etc/at.allow 파일의 소유자가 root입니다."				>> $CREATE_FILE 2>&1
	fi
	echo " "										>> $CREATE_FILE 2>&1
	if [ `ls -al /etc/at.allow | grep "^-..-.-----" | wc -l` -eq 0 ]
	  then
	    echo "＊/etc/at.allow 파일의 권한이 640을 초과합니다."			>> $CREATE_FILE 2>&1
		flag_3_22=0
	  else
	    echo "＊/etc/at.allow 파일의 권한이 640을 이하합니다."			>> $CREATE_FILE 2>&1
	fi
  else
    echo "＊/etc/at.allow 파일이 없습니다."						>> $CREATE_FILE 2>&1
fi
echo " "											>> $CREATE_FILE 2>&1

echo "② /etc/at.deny 파일확인"								>> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/at.deny ]
  then
    ls -al /etc/at.deny									>> $CREATE_FILE 2>&1
	echo " "										>> $CREATE_FILE 2>&1
	if [ `ls -al  /etc/at.deny | awk '$3 != "root"' | wc -l` -eq 1 ]
	  then
	    echo "＊ /etc/at.deny 파일의 소유자가 root가 아닙니다."			>> $CREATE_FILE 2>&1
		flag_3_22=0
	  else
	    echo "＊ /etc/at.deny 파일의 소유자가 root입니다."				>> $CREATE_FILE 2>&1
	fi
	echo " "										>> $CREATE_FILE 2>&1
	if [ `ls -al  /etc/at.deny | grep "^-..-.-----" | wc -l` -eq 0 ]
	  then
	    echo "＊ /etc/at.deny 파일의 권한이 640을 초과합니다."			>> $CREATE_FILE 2>&1
		flag_3_22=0
	  else
	    echo "＊ /etc/at.deny 파일의 권한이 640을 이하합니다."			>> $CREATE_FILE 2>&1
	fi
  else
    echo "＊ /etc/at.deny 파일이 없습니다."						>> $CREATE_FILE 2>&1
fi

echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1

echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $flag_3_22 -eq 1 ]
  then
    echo "[3.22] 양호"										>> $CREATE_FILE 2>&1
  else
    echo "[3.22] 취약"										>> $CREATE_FILE 2>&1
fi
echo " "											>> $CREATE_FILE 2>&1


echo "U-57 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-57 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       




echo "U-58 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-58 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                              3.23 SNMP 서비스 구동 점검                               " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: SNMP 서비스를 불필요한 용도로 사용하지 않을 경우 양호"                           >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
# SNMP서비스는 동작시 /etc/service 파일의 포트를 사용하지 않음.
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"											>> $CREATE_FILE 2>&1
echo "K@A@"											>> $CREATE_FILE 2>&1
if [ `ps -ef | grep snmp | grep -v "grep" | wc -l` -eq 0 ]
  then
    echo "＊SNMP Service Disable" >> $CREATE_FILE 2>&1
	flag_3_23=1
  else
    ps -ef | grep snmp | grep -v "grep" >> $CREATE_FILE 2>&1
	flag_3_23=0
fi
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "											>> $CREATE_FILE 2>&1

if [ $flag_3_23 -eq 1 ]
  then
    echo "[3.23] 양호" >> $CREATE_FILE 2>&1
  else
    echo "[3.23] 취약" >> $CREATE_FILE 2>&1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-58 END"                                              	                               >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-58 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "  




echo "U-59 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-59 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                     3.24 snmp 서비스 커뮤티니스트링의 복잡성 설정                     " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: SNMP Community 이름이 public, private 이 아닐 경우 양호"                         >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"											>> $CREATE_FILE 2>&1
echo "K@A@"											>> $CREATE_FILE 2>&1


if [ $flag_3_23 -eq 1 ]
  then
    echo "＊SNMP Service Disable" >> $CREATE_FILE 2>&1
  else
  flag_3_24=1

  echo "① SNMP Community String 설정 "															>> $CREATE_FILE 2>&1
  echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1

  if [ -f /etc/snmpd.conf ]
  then
	  echo "＊/etc/snmpd.conf 파일 설정:"                                                          >> $CREATE_FILE 2>&1
	  echo "------------------------------------------------------"                                >> $CREATE_FILE 2>&1
	  cat /etc/snmpd.conf | egrep -i "public|private" | grep -v "#"           												 >> $CREATE_FILE 2>&1
	  if [ `cat /etc/snmpd.conf | egrep -i "public|private" | grep -v "#" | wc -l` -gt 0 ]
	  then
	  flag_3_24=0
	  fi
  fi


  if [ -f /etc/snmp/snmpd.conf ]
  then
	  echo "＊/etc/snmp/snmpd.conf 파일 설정:"                                                          >> $CREATE_FILE 2>&1
	  echo "------------------------------------------------------"                                >> $CREATE_FILE 2>&1
	  cat /etc/snmp/snmpd.conf | egrep -i "public|private" | grep -v "#"           												 >> $CREATE_FILE 2>&1
	  if [ `cat /etc/snmp/snmpd.conf | egrep -i "public|private" | grep -v "#" | wc -l` -gt 0 ]
	  then
	  flag_3_24=0
	  fi
  fi

  if [ -f /etc/snmp/conf/snmpd.conf ]
  then
	  echo "＊/etc/snmpd.conf 파일 설정:"                                                          >> $CREATE_FILE 2>&1
	  echo "------------------------------------------------------"                                >> $CREATE_FILE 2>&1
	  cat /etc/snmp/conf/snmpd.conf | egrep -i "public|private" | grep -v "#"           												 >> $CREATE_FILE 2>&1
	  if [ `cat /etc/snmp/conf/snmpd.conf | egrep -i "public|private" | grep -v "#" | wc -l` -gt 0 ]
	  then
	  flag_3_24=0
	  fi
  fi
fi

echo "A@K@"											>> $CREATE_FILE 2>&1
echo "@@@@"											>> $CREATE_FILE 2>&1
echo " "                                                                                     >> $CREATE_FILE 2>&1

# SNMP 서비스가 종료되었을 경우 양호
if [ $flag_3_23 -eq 1 ]
  then
    echo "[3.24] 양호"								>> $CREATE_FILE 2>&1
  else
    if [ $flag_3_24 -eq 1 ]
	then
		echo "[3.24] 양호"								>> $CREATE_FILE 2>&1
	else
		echo "[3.24] 취약"								>> $CREATE_FILE 2>&1
    fi
fi



echo " "                                                                                     >> $CREATE_FILE 2>&1
echo "U-59 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-59 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       




echo "U-60 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-60 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                            3.25 로그온 시 경고 메시지 제공                            " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준 : 서버 및 Telnet 서비스에 로그온 메시지가 설정되어 있는 경우 경우 양호 "		>> $CREATE_FILE 2>&1
echo "■ 로그온 메시지가 없거나 메시지에 OS 버전 정보 및 호스트 이름이 들어간 경우 취약 "	>> $CREATE_FILE 2>&1
echo "■ 현황"																				>> $CREATE_FILE 2>&1

flag_3_25=1

echo "!@#$"																						>> $CREATE_FILE 2>&1
echo "K@A@"																						>> $CREATE_FILE 2>&1


echo "① /etc/motd 파일 설정"                                                                  >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/motd ]
then
	if [ `cat /etc/motd | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/motd | grep -v "^ *$"                                                 			>> $CREATE_FILE 2>&1
	else
		echo "경고 메시지 설정 내용이 없습니다."												>> $CREATE_FILE 2>&1
		flag_3_25=0
	fi
else
	echo "/etc/motd 파일이 없습니다.(취약)"                                                		>> $CREATE_FILE 2>&1
	flag_3_25=0
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② Telnet 서비스 배너 설정 확인"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "* /etc/services 파일에서 포트 확인:"                                                     >> $CREATE_FILE 2>&1
echo "-------------------------------------------------------------"                           >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp"                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "* 서비스 포트 활성화 여부 확인:"                                                         >> $CREATE_FILE 2>&1
echo "-------------------------------------------------------------"                           >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "LISTEN" | head -1 | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "LISTEN" | head -1                     			>> $CREATE_FILE 2>&1
		echo " "                                                                                >> $CREATE_FILE 2>&1
		echo "* /etc/default/telnetd 파일 설정:"                                                >> $CREATE_FILE 2>&1
        echo "BANNER=\"로그온 메시지 입력\" 확인"      											>> $CREATE_FILE 2>&1
        echo "-------------------------------------------------------------"                    >> $CREATE_FILE 2>&1
        if [ -f /etc/issue.net ]
        then
		    if [ `cat /etc/issue.net | grep -v "^#" | wc -l` -gt 0 ]
	        then
		        cat /etc/issue.net | grep -v "^#"                     							>> $CREATE_FILE 2>&1
	        else
		        cat /etc/issue.net 																>> $CREATE_FILE 2>&1
		        echo "BANNER 설정내용이 없습니다.(혹은 주석처리 되었습니다.)"			  		>> $CREATE_FILE 2>&1
		        flag_3_25=0
		    fi
        else
	      echo "/etc/issue.net 파일이 없습니다."												>> $CREATE_FILE 2>&1
	      flag_3_25=0
	    fi
	else
		echo "* Telnet Service Disable"                                               			>> $CREATE_FILE 2>&1
	fi
fi													
echo "A@K@"																						>> $CREATE_FILE 2>&1
echo "@@@@"																						>> $CREATE_FILE 2>&1
echo " "                                                                                        >> $CREATE_FILE 2>&1


if [ $flag_3_25 -eq 1 ]
then
    echo "[3.25] 수동점검"																		>> $CREATE_FILE 2>&1
else
    echo "[3.25] 취약"																			>> $CREATE_FILE 2>&1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-60 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-60 END"
unset flag_3_25
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       




echo "U-61 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-61 START" 
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                             3.26 NFS 설정 파일 접근 권한                              " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준 : NFS 접근제어 설정파일의 소유자가 root 이고, 권한이 644 이하인 경우 양호 "	>> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"																						>> $CREATE_FILE 2>&1
echo "K@A@"																						>> $CREATE_FILE 2>&1

flag_3_26=1

if [ $flag_3_06 -eq 1 ]
then
		echo "＊ NFS Service Disable"                                                               >> $CREATE_FILE 2>&1
else
  flag_3_26=1

  if [ -f /etc/exports ]
    then
      echo "① 파일소유자 점검"																	>> $CREATE_FILE 2>&1
      echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
      ls -al /etc/exports																		>> $CREATE_FILE 2>&1
	  echo " "																					>> $CREATE_FILE 2>&1
	  if [ `ls -al /etc/exports | awk '$3 != "root"' | wc -l` -eq 1 ]
	    then
	      ls -al /etc/exports																	>> $CREATE_FILE 2>&1
		  echo "* /etc/exports 파일의 소유자가 root가 아닙니다."								>> $CREATE_FILE 2>&1
		  flag_3_26=0
	    else
	      echo "* /etc/exports 파일의 소유자가 root입니다."										>> $CREATE_FILE 2>&1
	  fi
	  echo " "																					>> $CREATE_FILE 2>&1
	  echo "② 파일권한 점검"																	>> $CREATE_FILE 2>&1
      echo "------------------------------------------------------------------------------"   >> $CREATE_FILE 2>&1
	  if [ `ls -al /etc/exports | grep "^-..-.--.--" | wc -l` -eq 0 ]
	    then
	      echo "* /etc/exports 파일의 권한이 644을 초과합니다."									>> $CREATE_FILE 2>&1
		  flag_3_26=0
	    else
	      echo "* /etc/exports 파일의 권한이 644 이하입니다."									>> $CREATE_FILE 2>&1
	  fi
    else
	  echo "* /etc/exports 파일이 없습니다."													>> $CREATE_FILE 2>&1
	  flag_3_26=0
  fi

fi
echo "A@K@"																						>> $CREATE_FILE 2>&1
echo "@@@@"																						>> $CREATE_FILE 2>&1
echo " "                                                                                        >> $CREATE_FILE 2>&1
if [ $flag_3_06 -eq 1 ]
	then
	echo "[3.26] 양호"																			>> $CREATE_FILE 2>&1
else
	if [ $flag_3_26 -eq 1 ]
	then
		echo "[3.26] 양호"																		>> $CREATE_FILE 2>&1
	else
		echo "[3.26] 취약"																		>> $CREATE_FILE 2>&1
	fi

fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-61 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-61 END"
unset flag_3_26
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       




echo "U-62 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-62 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                              3.27 expn, vrfy 명령어 제한                              " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: SMTP 서비스를 사용하지 않거나 noexpn, novrfy 옵션이 설정되어 있을 경우 양호"     >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
flag_3_27=1

if [ $flag_3_12_1 -eq 1 ]
  then
    echo "＊Sendmail Service Disable"							>> $CREATE_FILE 2>&1
else
  echo "/etc/mail/sendmail.cf 파일 옵션 확인"									>> $CREATE_FILE 2>&1
  echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
  if [ -f /etc/mail/sendmail.cf ]
    then
      if [ `cat /etc/mail/sendmail.cf | grep -i "O PrivacyOptions" | grep -i "noexpn" | grep -i "novrfy" |grep -v "#" |wc -l ` -eq 0 ]
	    then
	    echo "＊noexpn, novrfy 옵션 설정 없음"				>> $CREATE_FILE 2>&1
		flag_3_27=0
	  else
	    cat /etc/mail/sendmail.cf | grep -i "O PrivacyOptions"					>> $CREATE_FILE 2>&1
	  fi
  else
    echo "＊/etc/mail/sendmail.cf 파일이 존재하지 않습니다."					>> $CREATE_FILE 2>&1
	flag_3_27=0
  fi
fi

echo "A@K@"											>> $CREATE_FILE 2>&1
echo "@@@@"										        >> $CREATE_FILE 2>&1
echo " " 											>> $CREATE_FILE 2>&1

if [ $flag_3_12_1 -eq 1 ] || [ $flag_3_27 -eq 1 ]
  then
    echo "[3.27] 양호"										>> $CREATE_FILE 2>&1
  else
    echo "[3.27] 취약"										>> $CREATE_FILE 2>&1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-62 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-62 END" 
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                                   4. 패치 관리                                        " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "U-63 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-63 START" - longtime 
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                       4.01 최신 보안패치 및 벤더 권고사항 적용                        " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 패치 적용 정책을 수립하여 주기적으로 패치를 관리하고 있을 경우 양호"             >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
echo "＊현재 등록된 서비스"                                                                   >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
rpm -qa |sort > $TMP/4.01.txt


cat $TMP/4.01.txt | head -5										>> $CREATE_FILE 2>&1
echo "...중략..."										>> $CREATE_FILE 2>&1
cat $TMP/4.01.txt | tail -5										>> $CREATE_FILE 2>&1
echo "A@K@"										       >> $CREATE_FILE 2>&1
echo "@@@@"										       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[4.01] 수동점검" 									       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1	
echo "U-63 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-63 END"
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       




echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                                   5. 로그 관리                                        " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "U-64 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-64 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                            5.01 로그의 정기적 검토 및 보고                            " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 로그기록에 대해 정기적 검토, 분석, 리포트 작성 및 보고가 이루어지고 있는 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo "!@#$"											>> $CREATE_FILE 2>&1
echo "K@A@"											>> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "＊담당자 인터뷰 및 증적확인"                                                            >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo "① 일정 주기로 로그를 점검하고 있는가?"                                                  >> $CREATE_FILE 2>&1
echo "② 로그 점검결과에 따른 결과보고서가 존재하는가?"                                        >> $CREATE_FILE 2>&1
echo "A@K@"											>> $CREATE_FILE 2>&1
echo "@@@@"											>> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "[5.01] 수동점검" 										>> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-64 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-64 END"                                                                                
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       

echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "----#/etc/passwd#start----"                                                               >> $CREATE_FILE 2>&1
echo "/etc/passwd"                                                                              >> $CREATE_FILE 2>&1
cat /etc/passwd											>> $CREATE_FILE 2>&1
echo "----#/etc/passwd#end----"                                                                >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       



echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "----#/etc/shadow#start----"                                                               >> $CREATE_FILE 2>&1
echo "/etc/shadow"                                                                              >> $CREATE_FILE 2>&1
cat /etc/shadow											>> $CREATE_FILE 2>&1
echo "----#/etc/shadow#end----"                                                                >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       



echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "----#SUID~#start----"									>> $CREATE_FILE 2>&1
echo "SUID~"											>> $CREATE_FILE 2>&1
cat $TMP/2.08.txt										>> $CREATE_FILE 2>&1
echo "----#SUID~#end----"                                                                >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "----#world#start----"									>> $CREATE_FILE 2>&1
echo "world writable"                                                                     >> $CREATE_FILE 2>&1
cat $TMP/2.10.txt											>> $CREATE_FILE 2>&1
echo "----#world#end----"                                                                >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "



echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "----#hiddenfile#start----"									>> $CREATE_FILE 2>&1
echo "hiddenfile"                                                                     >> $CREATE_FILE 2>&1
cat $TMP/2.19.txt										>> $CREATE_FILE 2>&1
echo "----#hiddenfile#end----"                                                                >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "----#patchfile#start----"									>> $CREATE_FILE 2>&1
echo "patchfile"                                                                     >> $CREATE_FILE 2>&1
cat $TMP/4.01.txt									          >> $CREATE_FILE 2>&1											
echo "----#patchfile#end----"                                                                >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "

rm -rf $TMP




echo "U-65 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-65 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                           5.02 정책에 따른 시스템 로깅 설정                           " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: syslog 에 중요 로그 정보에 대한 설정이 되어 있을 경우 양호"                      >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "!@#$"										       >> $CREATE_FILE 2>&1
echo "K@A@"										       >> $CREATE_FILE 2>&1
flag_5_2_1=1
flag_5_2_2=2
flag_5_2_3=2

echo "① SYSLOG 데몬 동작 확인"                                                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep -i 'syslog' | grep -v 'grep' | wc -l` -eq 0 ]
then
	echo "＊SYSLOG Service Disable"                                                             >> $CREATE_FILE 2>&1
	flag_5_2_1=0
else
	ps -ef | grep -i 'syslog' | grep -v 'grep'                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② SYSLOG 설정 확인"                                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/syslog.conf ]
then
	if [ `cat /etc/syslog.conf | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/syslog.conf | grep -v "^#" | grep -v "^ *$"				>> $CREATE_FILE 2>&1
	else
		echo "/etc/syslog.conf 파일에 설정 내용이 없습니다."                   >> $CREATE_FILE 2>&1
		flag_5_2_2=`expr $flag_5_2_2 - 1`
	fi
else
	echo "/etc/syslog.conf 파일이 없습니다."                                                    >> $CREATE_FILE 2>&1
	flag_5_2_3=`expr $flag_5_2_3 - 1`
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ rsyslog 설정 확인"                                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/rsyslog.conf ]
then
	if [ `cat /etc/rsyslog.conf | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/rsyslog.conf | grep -v "^#" | grep -v "^ *$"					>> $CREATE_FILE 2>&1
	else
		echo "/etc/rsyslog.conf 파일에 설정 내용이 없습니다."                >> $CREATE_FILE 2>&1
		flag_5_2_2=`expr $flag_5_2_2 - 1`
	fi
else
	echo "/etc/rsyslog.conf 파일이 없습니다."                                                    >> $CREATE_FILE 2>&1
	flag_5_2_3=`expr $flag_5_2_3 - 1`
	fi
echo "A@K@"											>> $CREATE_FILE 2>&1
echo "@@@@"											>> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $flag_5_2_1 -eq 1 ]
then
echo "[5.02] 양호"									>> $CREATE_FILE 2>&1
else
    if [ $flag_5_2_3 -eq 0 ]
	  then
	  echo "[5.02] 취약"																	 >> $CREATE_FILE 2>&1
	else
	  if [ $flag_5_2_2 -eq 0 ]
	  then
	    echo "[5.02] 취약"																	 >> $CREATE_FILE 2>&1
	  else
	    echo "[5.02] 취약"																	 >> $CREATE_FILE 2>&1	    
	  fi
	fi
fi






echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-65 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-65 END" 
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       
rm -rf 5.02.txt




echo "============================== System Information Start ===============================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "###############################  Kernel Information  ##################################" >> $CREATE_FILE 2>&1
uname -a                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "################################## IP Information #####################################" >> $CREATE_FILE 2>&1
ifconfig -a                                                                                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "################################   Network Status   ###################################" >> $CREATE_FILE 2>&1
netstat -an | egrep -i "LISTEN|ESTABLISHED"                                                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "################################   Network Port&Service   #############################" >> $CREATE_FILE 2>&1
netstat -tnlp | grep -v 127.0.0.1 | sed 's/:::/0 /g' | sed 's/[:\/]/ /g' | awk '{print $5"\t"$10}' | sort -ug  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#############################   Routing Information   #################################" >> $CREATE_FILE 2>&1
netstat -rn                                                                                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "################################   Process Status   ###################################" >> $CREATE_FILE 2>&1
ps -ef                                                                                         >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "###################################   User Env   ######################################" >> $CREATE_FILE 2>&1
env                                                                                            >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "============================== System Information End =================================" >> $CREATE_FILE 2>&1




echo "***************************************** END *****************************************" >> $CREATE_FILE 2>&1
date                                                                                           >> $CREATE_FILE 2>&1
echo "***************************************** END *****************************************"

