#!/bin/sh
LANG=C
export LANG
alias ls=ls

# Apache Vulnerability Scanner
# Apache (UNIX&LINUX - RedHat 계열.) 취약점 점검



CREATE_FILE=`hostname`"_Apache_"`date +%m%d%k%M`.txt
echo > $CREATE_FILE 2>&1
echo > PATH_HTTPD_CONF_tmp 2>&1



echo " "
echo " " >> $CREATE_FILE 2>&1


echo "############################# Start Time #######################################"
echo "############################# Start Time #######################################" >> $CREATE_FILE 2>&1
date
date >> $CREATE_FILE 2>&1
echo " "
echo "=============================  Apache Security Check  ==============================" 	   >> $CREATE_FILE 2>&1
echo "=============================  Apache Security Check  ==============================" 
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "U-01 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-01 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                           1.01 Apache 디렉토리 리스팅 제거                            " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: httpd.conf 파일의 Directory 부분의 Options 지시자에 Indexes가 설정되어 있지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
############################### 홈디렉터리 경로 구하기(시작) ##################################

apache_service_online=1

if [ `ps -ef | grep httpd | grep -v "grep" | wc -l` -eq 0 ]
  then
    
    apache_service_online=0
	echo "☞ Apache 서비스가 활성화되어 있지 않습니다."
    echo "☞ Apache 서비스가 활성화되어 있지 않습니다." >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	## apache 서비스가 활성화되어 있지 않은 경우 결과 파일 생성 후 바로 종료
	echo "************************************************** END **************************************************"
	echo "************************************************** END **************************************************">> $CREATE_FILE 2>&1
	
	CREATE_FILE_RESULT=`hostname`"_Apache_"`date +%m%d%k%M`.txt
	echo > $CREATE_FILE_RESULT
	cat $CREATE_FILE >> $CREATE_FILE_RESULT 2>&1
	rm -Rf PATH_HTTPD_CONF_tmp 2>&1
	rm -Rf $CREATE_FILE 2>&1
	exit 
	
	
  else
    echo "* Apache 서비스가 사용 중입니다."							>> $CREATE_FILE 2>&1
    echo " "														>> $CREATE_FILE 2>&1
    ## apache 환경 출력 구문들
    PATH_HTTPD=`ps -ef | grep httpd | grep -v "grep" | awk '{for(i=1;i<=NF;i++) {if ($(i) ~ /^\// && $(i) ~/httpd$/) print $(i) }}'|sort -u`
    #$PATH_HTTPD -V >> $CREATE_FILE 2>&1
    ##
    #################### httpd.conf 관련 파일이 여러개 있을 경우 경로를 PATH_HTTPD_CONF 파일로 저장하기 위한 구문들 ##########################
    #apache 서비스를 -f 옵션을 주고 실행하였을때 ps -ef 에서 conf 파일이 출력되므로 추가
    `ps -ef | grep httpd | grep -v "grep" | awk '{for(i=1;i<=NF;i++) {if ($(i) ~ /^\// && $(i) ~/conf$/) print $(i) }}'|sort -u`	>> PATH_HTTPD_CONF_tmp 2>&1
    
    #SERVER_CONFIG_FILE 에서 절대경로로 되어 있으면 추가
    $PATH_HTTPD -V | grep SERVER_CONFIG_FILE | awk -F"\"" '{print $2}' | grep '^/'							>> PATH_HTTPD_CONF_tmp 2>&1
    
    #SERVER_CONFIG_FILE이 상대경로일 경우 HTTPD_ROOT 까지 확인
    if [ `$PATH_HTTPD -V | grep SERVER_CONFIG_FILE | awk -F"\"" '{print $2}' | grep '^/' | wc -l` -eq 0 ] 
      then
        HTTPD_ROOT=`$PATH_HTTPD -V | grep HTTPD_ROOT | awk -F"\"" '{print $2}'`
        SERVER_CONFIG_FILE=`$PATH_HTTPD -V | grep SERVER_CONFIG_FILE | awk -F"\"" '{print $2}'`
        echo $HTTPD_ROOT"/"$SERVER_CONFIG_FILE																>> PATH_HTTPD_CONF_tmp 2>&1
      else
	:
    fi
    
    #중복된 conf 파일 제거
    cat PATH_HTTPD_CONF_tmp | awk '{for(i=1;i<=NF;i++){print $(i)}}' | sort -u								> PATH_HTTPD_CONF 2>&1 
    unset tmp
    unset PATH_APACHE
    unset HTTPD_ROOT
    unset SERVER_CONFIG_FILE
    rm -Rf PATH_HTTPD_CONF_tmp
	
	
	
	echo "* apache httpd.conf 경로  "								>> $CREATE_FILE 2>&1
	cat PATH_HTTPD_CONF												>> $CREATE_FILE 2>&1

fi



################################ 홈디렉터리 경로 구하기(끝) ###################################


if [ $apache_service_online -eq 1 ]
then
  echo "!@#$"													>> $CREATE_FILE 2>&1
  echo "K@A@"													>> $CREATE_FILE 2>&1
  result_1_01=1
  is_conf=0 # 전체적으로 모든 항목에 적용됨. conf 파일이 실제로 모두 존재하지 않으면 결과적으로 0이 됨
  for httpd_conf in `cat PATH_HTTPD_CONF`;do
	  echo "① $httpd_conf 파일 내용 중 Options Indexes 설정 확인"						>> $CREATE_FILE 2>&1
	  echo "------------------------------------------------------------------------------"			>> $CREATE_FILE 2>&1
	  if [ -f $httpd_conf ]
	    then
		  is_conf=1 # conf 파일이 아무것도 없을 때 0이 되고 결과적으로 미점검이 됨
		  if [ `cat $httpd_conf | grep -v "^#" | grep -i "Options Indexes" | wc -l` -eq 0 ]
		    then			
			  echo "* Indexes 옵션이 설정되어 있지 않습니다."						>> $CREATE_FILE 2>&1
		    else	
			  cat -n $httpd_conf | awk '$2 !~ /^#/' | grep -i "Options Indexes"			>> $CREATE_FILE 2>&1
			  result_1_01=0
			  echo " "										>> $CREATE_FILE 2>&1
			  echo "* Indexes 옵션이 설정되어 있습니다."						>> $CREATE_FILE 2>&1
		  fi
	    else
		  echo "* $httpd_conf 파일이 없습니다."								>> $CREATE_FILE 2>&1 
	  fi
	  echo " "												>> $CREATE_FILE 2>&1
  done
  echo "A@K@"													>> $CREATE_FILE 2>&1
  echo "@@@@"													>> $CREATE_FILE 2>&1
else
  echo "!@#$"													>> $CREATE_FILE 2>&1
  echo "K@A@"													>> $CREATE_FILE 2>&1
    echo "* Apache 서비스 미사용 중입니다."						>> $CREATE_FILE 2>&1 
  echo "A@K@"													>> $CREATE_FILE 2>&1
  echo "@@@@"													>> $CREATE_FILE 2>&1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $apache_service_online -eq 1 ]
  then
    if [ $is_conf -eq 0 ]; then
      echo "[1.01] 수동점검 - httpd.conf 파일을 찾을 수 없습니다."						>> $CREATE_FILE 2>&1
    elif [ $result_1_01 -eq 1 ]; then
      echo "[1.01] 양호"											>> $CREATE_FILE 2>&1
    elif [ $result_1_01 -eq 0 ]; then
      echo "[1.01] 취약"											>> $CREATE_FILE 2>&1  
    else
      :
    fi
  else
    echo "[1.01] 양호"												>> $CREATE_FILE 2>&1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-01 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-01 END"
unset result_1_01
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       



echo "U-02 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-02 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                          1.02 Apache 웹 프로세스 권한 제한                            " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 웹 프로세스 권한을 제한 했을 경우 양호(User root, Group root 가 아닌 경우)"      >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $apache_service_online -eq 1 ]
then

  echo "!@#$"										       >> $CREATE_FILE 2>&1
  echo "K@A@"										       >> $CREATE_FILE 2>&1
  result_1_02=1
  for httpd_conf in `cat PATH_HTTPD_CONF`;do
	  echo "① $httpd_conf 파일 내용에서 root 권한 확인"						>> $CREATE_FILE 2>&1
	  echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	  if [ -f $httpd_conf ]
	    then
		  cat -n $httpd_conf | awk '($2 !~ /^#/)'| awk '$2 ~ /^User/ || $2 ~ /^Group/'			>> $CREATE_FILE 2>&1
		  if [ `cat $httpd_conf | grep -v "^#" | egrep -i "^user|^group"| grep "root" | wc -l` -eq 0 ]
		    then			
			  echo "* Apache 데몬이 root 권한으로 되어 있지 않습니다."				>> $CREATE_FILE 2>&1
		    else	
			  result_1_02=0
			  echo "* Apache 데몬이 root 권한으로 되어 있습니다."					>> $CREATE_FILE 2>&1
		  fi
	    else
		  echo "* $httpd_conf 파일이 없습니다."								>> $CREATE_FILE 2>&1 
	  fi
	  echo " "												>> $CREATE_FILE 2>&1
  done

  echo "A@K@"													>> $CREATE_FILE 2>&1
  echo "@@@@"													>> $CREATE_FILE 2>&1

else
  echo "!@#$"													>> $CREATE_FILE 2>&1
  echo "K@A@"													>> $CREATE_FILE 2>&1
    echo "* Apache 서비스 미사용 중입니다."						>> $CREATE_FILE 2>&1 
  echo "A@K@"													>> $CREATE_FILE 2>&1
  echo "@@@@"													>> $CREATE_FILE 2>&1
fi

echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $apache_service_online -eq 1 ]
  then
    if [ $is_conf -eq 0 ]; then
      echo "[1.02] 수동점검 - httpd.conf 파일을 찾을 수 없습니다."						>> $CREATE_FILE 2>&1
    elif [ $result_1_02 -eq 1 ]; then
      echo "[1.02] 양호"											>> $CREATE_FILE 2>&1
    elif [ $result_1_02 -eq 0 ]; then
      echo "[1.02] 취약"											>> $CREATE_FILE 2>&1  
    else
      :
    fi
  else
    echo "[1.02] 양호"												>> $CREATE_FILE 2>&1
fi


echo " "												>> $CREATE_FILE 2>&1
echo "U-02 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-02 END"
unset result_1_02
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       





echo "U-03 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-03 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                          1.03 Apache 상위 디렉토리 접근 금지                          " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: httpd.conf 파일의 Directory 부분의 AllowOverride None 설정이 아니면양호"        >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $apache_service_online -eq 1 ]
then

  echo "!@#$"											>> $CREATE_FILE 2>&1
  echo "K@A@"											>> $CREATE_FILE 2>&1


  result_1_03=1
  for httpd_conf in `cat PATH_HTTPD_CONF`;do
      echo "① $httpd_conf 파일 내용에서 Authconfig 옵션 확인"						>> $CREATE_FILE 2>&1
      echo "------------------------------------------------------------------------------"		>> $CREATE_FILE 2>&1
      if [ -f $httpd_conf ]
	    then
	      cat -n $httpd_conf | awk '($2 !~ /^#/)'| grep -i "AllowOverride">> $CREATE_FILE 2>&1
		  echo " "										>> $CREATE_FILE 2>&1
	      if [ `cat $httpd_conf | grep -v "^#" | egrep -i "AllowOverride"| grep -i "None" | wc -l` -ne 0 ]
		    then			
			  echo "* AllowOverride 옵션에서 None으로 설정되어 있습니다."			>> $CREATE_FILE 2>&1
			  result_1_03=0
	 	    else	
		      echo "* AllowOverride 옵션에서 None으로 설정되어 있지 않습니다."			 >> $CREATE_FILE 2>&1
	      fi
	        else
	          echo "* $httpd_conf 파일이 없습니다."							>> $CREATE_FILE 2>&1 
      fi
	  echo " "											>> $CREATE_FILE 2>&1
  done

  echo "A@K@"												>> $CREATE_FILE 2>&1
  echo "@@@@"												>> $CREATE_FILE 2>&1

else
  echo "!@#$"													>> $CREATE_FILE 2>&1
  echo "K@A@"													>> $CREATE_FILE 2>&1
    echo "* Apache 서비스 미사용 중입니다."						>> $CREATE_FILE 2>&1 
  echo "A@K@"													>> $CREATE_FILE 2>&1
  echo "@@@@"													>> $CREATE_FILE 2>&1
fi


echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $apache_service_online -eq 1 ]
  then
    if [ $is_conf -eq 0 ]; then
      echo "[1.03] 수동점검 - httpd.conf 파일을 찾을 수 없습니다."					>> $CREATE_FILE 2>&1
    elif [ $result_1_03 -eq 1 ]; then
      echo "[1.03] 양호"										>> $CREATE_FILE 2>&1
    elif [ $result_1_03 -eq 0 ]; then
      echo "[1.03] 취약"										>> $CREATE_FILE 2>&1  
    else
      :
    fi
  else
    echo "[1.03] 양호"											>> $CREATE_FILE 2>&1
fi


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-03 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-03 END"
unset result_1_03
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "





echo "U-04 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-04 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                               1.04 Apache 링크 사용 금지                              " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: Options 지시자에서 심블릭 링크를 가능하게 하는 옵션인 FollowSymLinks가 제거된 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $apache_service_online -eq 1 ]
then


  echo "!@#$"										       >> $CREATE_FILE 2>&1
  echo "K@A@"										       >> $CREATE_FILE 2>&1


  result_1_04=1

  for httpd_conf in `cat PATH_HTTPD_CONF`;do
      echo "① $httpd_conf 파일에서 FollowSymLinks 옵션 확인"					>> $CREATE_FILE 2>&1
      echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	  if [ -f $httpd_conf ]
	    then
	      cat -n $httpd_conf | awk '$2 !~ /^#/' | grep -i FollowSymLinks			>> $CREATE_FILE 2>&1
		  echo " "									>> $CREATE_FILE 2>&1
		  if [ `cat -n $httpd_conf | awk '$2 !~ /^#/' | grep -i FollowSymLinks | wc -l` -eq 0 ]
		    then
		      echo "* FollowSymLinks 옵션이 설정되어 있지 않습니다."			>> $CREATE_FILE 2>&1
		    else
		      echo "* FollowSymLinks 옵션이 설정되었습니다."				>> $CREATE_FILE 2>&1
			  result_1_04=0
		  fi
	    else
	      echo "* $httpd_conf 파일이 없습니다."						>> $CREATE_FILE 2>&1 
	  fi
	  echo " "										>> $CREATE_FILE 2>&1
  done


  echo "A@K@"												>> $CREATE_FILE 2>&1
  echo "@@@@"												>> $CREATE_FILE 2>&1

else
  echo "!@#$"													>> $CREATE_FILE 2>&1
  echo "K@A@"													>> $CREATE_FILE 2>&1
    echo "* Apache 서비스 미사용 중입니다."						>> $CREATE_FILE 2>&1 
  echo "A@K@"													>> $CREATE_FILE 2>&1
  echo "@@@@"													>> $CREATE_FILE 2>&1
fi 


echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $apache_service_online -eq 1 ]
  then
    if [ $is_conf -eq 0 ]; then
      echo "[1.04] 수동점검 - httpd.conf 파일을 찾을 수 없습니다."					>> $CREATE_FILE 2>&1
    elif [ $result_1_04 -eq 1 ]; then
      echo "[1.04] 양호"										>> $CREATE_FILE 2>&1
    elif [ $result_1_04 -eq 0 ]; then
      echo "[1.04] 취약"										>> $CREATE_FILE 2>&1  
    else
      :
    fi
  else
    echo "[1.04] 양호"											>> $CREATE_FILE 2>&1
fi


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-04 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-04 END"
unset result_1_04
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "







echo "U-05 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-05 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                        1.05 Apache 파일 업로드 및 다운로드 제한                       " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 시스템에 따라 파일 업로드 및 다운로드에 대한 용량이 제한되어 있는 경우 양호"     >> $CREATE_FILE 2>&1
echo "■       : <Directory 경로>의 LimitRequestBody 지시자에 제한용량이 설정되어 있는 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $apache_service_online -eq 1 ]
then


  echo "!@#$"											>> $CREATE_FILE 2>&1
  echo "K@A@"											>> $CREATE_FILE 2>&1




  result_1_05=1

  for httpd_conf in `cat PATH_HTTPD_CONF`;do
      echo "① $httpd_conf 파일에서 파일 업로드 및 다운로드 제한 확인"				>> $CREATE_FILE 2>&1
      echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	  if [ -f $httpd_conf ]
	    then
	      echo "\t-Directory 리스트"								>> $CREATE_FILE 2>&1
	      cat -n $httpd_conf | awk '$2 !~ /^#/' | grep -i "<Directory"			>> $CREATE_FILE 2>&1
		  cat -n $httpd_conf | awk '$2 !~ /^#/' | grep -i "<Directory" | wc -l		>> $CREATE_FILE 2>&1
		  echo " "									>> $CREATE_FILE 2>&1
		  echo "\t-LimitRequestBody 설정 개수"						>> $CREATE_FILE 2>&1
		  cat -n $httpd_conf | awk '$2 !~ /^#/' | grep -i "LimitRequestBody"		>> $CREATE_FILE 2>&1
		  cat -n $httpd_conf | awk '$2 !~ /^#/' | grep -i "LimitRequestBody" | wc -l	>> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1
		  if [ `cat -n $httpd_conf | awk '$2 !~ /^#/' | grep -i "<Directory" | wc -l` -eq `cat -n $httpd_conf | awk '$2 !~ /^#/' | grep -i "LimitRequestBody" | wc -l` ]
		    then
			  echo "* 모든 디렉터리의 LimitRequestBody 설정이 되어 있습니다."		>> $CREATE_FILE 2>&1
		    else
		      echo "* 모든 디렉터리의 LimitRequestBody 설정이 되어 있지 않습니다."	>> $CREATE_FILE 2>&1
			  result_1_05=0
		  fi
	    else
	      echo "* $httpd.conf 파일이 없습니다."						>> $CREATE_FILE 2>&1 
	  fi
	  echo " "										>> $CREATE_FILE 2>&1
  done


  echo "A@K@"												>> $CREATE_FILE 2>&1
  echo "@@@@"												>> $CREATE_FILE 2>&1
 
else
  echo "!@#$"													>> $CREATE_FILE 2>&1
  echo "K@A@"													>> $CREATE_FILE 2>&1
    echo "* Apache 서비스 미사용 중입니다."						>> $CREATE_FILE 2>&1 
  echo "A@K@"													>> $CREATE_FILE 2>&1
  echo "@@@@"													>> $CREATE_FILE 2>&1
fi 



echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $apache_service_online -eq 1 ]
  then
    if [ $is_conf -eq 0 ]; then
      echo "[1.05] 수동점검 - httpd.conf 파일을 찾을 수 없습니다."					>> $CREATE_FILE 2>&1
    elif [ $result_1_05 -eq 1 ]; then
      echo "[1.05] 양호"										>> $CREATE_FILE 2>&1
    elif [ $result_1_05 -eq 0 ]; then
      echo "[1.05] 취약"										>> $CREATE_FILE 2>&1  
    else
      :
    fi
  else
    echo "[1.05] 양호"											>> $CREATE_FILE 2>&1
fi



echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-05 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-05 END"
unset result_1_05
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " " 






echo "U-06 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-06 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                           1.06 Apache 웹 서비스 영역의 분리                           " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: DocumentRoot를 기본 디렉터리(~/apache/htdocs)가 아닌 별도의 디렉토리로 지정한 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                   >> $CREATE_FILE 2>&1
echo " "                                                                                        >> $CREATE_FILE 2>&1

if [ $apache_service_online -eq 1 ]
then

  echo "!@#$"											>> $CREATE_FILE 2>&1
  echo "K@A@"											>> $CREATE_FILE 2>&1


  result_1_06=1

  for httpd_conf in `cat PATH_HTTPD_CONF`;do
      echo "① $httpd_conf 파일에서 DocumentRoot 경로 확인"					>> $CREATE_FILE 2>&1
      echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	  if [ -f $httpd.conf ]
	    then
	      cat -n $httpd.conf | awk '$2 !~ /^#/' | grep -i DocumentRoot			>> $CREATE_FILE 2>&1
		  echo " "									>> $CREATE_FILE 2>&1
		  if [ `cat -n $httpd.conf | awk '$2 !~ /^#/' | grep -i DocumentRoot | grep "/usr/local/apache" |wc -l` -eq 0 ]
		    then
			  echo "* DocumentRoot 경로가 /usr/local/apache/htdocs으로 설정되어 있지 않습니다."   >> $CREATE_FILE 2>&1
		    else
			  echo "* DocumentRoot 경로가 /usr/local/apache/htdocs으로 설정되어 있습니다."	>> $CREATE_FILE 2>&1
			  result_1_06=0
		  fi
	    else
	      echo "* $httpd.conf 파일이 없습니다."							>> $CREATE_FILE 2>&1 
	  fi
	  echo " "											>> $CREATE_FILE 2>&1
  done
  echo " "												>> $CREATE_FILE 2>&1


  echo "A@K@"												>> $CREATE_FILE 2>&1
  echo "@@@@"												>> $CREATE_FILE 2>&1
  
else
  echo "!@#$"													>> $CREATE_FILE 2>&1
  echo "K@A@"													>> $CREATE_FILE 2>&1
    echo "* Apache 서비스 미사용 중입니다."						>> $CREATE_FILE 2>&1 
  echo "A@K@"													>> $CREATE_FILE 2>&1
  echo "@@@@"													>> $CREATE_FILE 2>&1
fi 


echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $apache_service_online -eq 1 ]
  then
    if [ $is_conf -eq 0 ]; then
      echo "[1.06] 수동점검 - httpd.conf 파일을 찾을 수 없습니다."					>> $CREATE_FILE 2>&1
    elif [ $result_1_06 -eq 1 ]; then
      echo "[1.06] 양호"										>> $CREATE_FILE 2>&1
    elif [ $result_1_06 -eq 0 ]; then
      echo "[1.06] 취약"										>> $CREATE_FILE 2>&1  
    else
      :
    fi
  else
    echo "[1.06] 양호"											>> $CREATE_FILE 2>&1
fi



echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-06 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-06 END"
unset result_1_06
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "





echo "U-07 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-07 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                            1.07 Apache 웹서비스 정보 숨김                             " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: ServerTokens 지시자로 헤더에 전송되는 정보를 설정할 수 있음.(ServerTokens Prod 설정인 경우 양호)" >> $CREATE_FILE 2>&1
echo "■       : ServerTokens Prod 설정이 없는 경우 Default 설정(ServerTokens Full)이 적용됨."  >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $apache_service_online -eq 1 ]
then


  echo "!@#$"											>> $CREATE_FILE 2>&1
  echo "K@A@"											>> $CREATE_FILE 2>&1


  result_1_07=1

  for httpd_conf in `cat PATH_HTTPD_CONF`;do
      echo "① $httpd_conf 파일에서 ServerTokens 지시자에 Prod 옵션이 설정 확인"			>> $CREATE_FILE 2>&1
      echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	  if [ -f $httpd_conf ]
	    then
	      echo "\t-Directory 리스트"								>> $CREATE_FILE 2>&1
	      cat -n $httpd_conf | awk '$2 !~ /^#/' | grep -i "<Directory"			>> $CREATE_FILE 2>&1
		  echo "총 "`cat -n $httpd_conf | awk '$2 !~ /^#/' | grep -i "<Directory" | wc -l`" 개" >> $CREATE_FILE 2>&1
		  echo " "									>> $CREATE_FILE 2>&1
		  echo "\t-prod 설정 개수"							>> $CREATE_FILE 2>&1
		  cat -n $httpd_conf | awk '$2 !~ /^#/' | grep -i "prod"				>> $CREATE_FILE 2>&1
		  echo "총 "`cat -n $httpd_conf | awk '$2 !~ /^#/' | grep -i "prod" | wc -l`" 개" >> $CREATE_FILE 2>&1
		  echo " "									>> $CREATE_FILE 2>&1
		  if [ `cat $httpd_conf | awk '$1 !~ /^#/' | grep -i "<Directory" | wc -l` -eq `cat $httpd_conf | awk '$1 !~ /^#/' | grep -i "prod" | wc -l` ]
		    then
		      echo "* 모든 디렉터리의 Prod 설정이 되어 있습니다."				>> $CREATE_FILE 2>&1
		    else
		      echo "* 모든 디렉터리의 Prod 설정이 되어 있지 않습니다."			>> $CREATE_FILE 2>&1
			  result_1_07=0
		  fi
	    else
	      echo "* $httpd_conf 파일이 없습니다."						>> $CREATE_FILE 2>&1 
	  fi
	  echo " "										>> $CREATE_FILE 2>&1
  done


  echo "A@K@"												>> $CREATE_FILE 2>&1
  echo "@@@@"												>> $CREATE_FILE 2>&1
  
else
  echo "!@#$"													>> $CREATE_FILE 2>&1
  echo "K@A@"													>> $CREATE_FILE 2>&1
    echo "* Apache 서비스 미사용 중입니다."						>> $CREATE_FILE 2>&1 
  echo "A@K@"													>> $CREATE_FILE 2>&1
  echo "@@@@"													>> $CREATE_FILE 2>&1
fi 



echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $apache_service_online -eq 1 ]
  then
    if [ $is_conf -eq 0 ]; then
      echo "[1.07] 수동점검 - httpd.conf 파일을 찾을 수 없습니다."					>> $CREATE_FILE 2>&1
    elif [ $result_1_07 -eq 1 ]; then
      echo "[1.07] 양호"										>> $CREATE_FILE 2>&1
    elif [ $result_1_07 -eq 0 ]; then
      echo "[1.07] 취약"										>> $CREATE_FILE 2>&1  
    else
      :
    fi
  else
    echo "[1.07] 양호"											>> $CREATE_FILE 2>&1
fi



echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-07 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-07 END"
unset result_1_07
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "





echo "U-08 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-08 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                            1.08 Apache MultiViews 옵션 제한                           " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: MultiViews 옵션이 없는 경우 양호" 							   				   >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $apache_service_online -eq 1 ]
then


  echo "!@#$"											>> $CREATE_FILE 2>&1
  echo "K@A@"											>> $CREATE_FILE 2>&1


  result_1_08=1

  for httpd_conf in `cat PATH_HTTPD_CONF`;do
      echo "① $httpd_conf 파일에서 MultiViews 옵션이 설정 확인"									 >> $CREATE_FILE 2>&1
      echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	  if [ -f $httpd_conf ]
	    then
	      cat $httpd_conf | grep MultiViews | grep -v "\#" 								>> $CREATE_FILE 2>&1
		  echo " "                                                                      >> $CREATE_FILE 2>&1
		  if [ `cat $httpd_conf | grep MultiViews | egrep -v "\#" | wc -l` -eq 0 ]
		    then
			  echo "* MultiViews 설정이 되어 있지 않습니다."								>> $CREATE_FILE 2>&1
		    else
			  echo "* MultiViews 설정이 되어 있습니다."						>> $CREATE_FILE 2>&1
			  result_1_08=0
		  fi
	    else
	      echo "* $httpd_conf 파일이 없습니다."						>> $CREATE_FILE 2>&1 
	  fi
	  echo " "										>> $CREATE_FILE 2>&1
  done


  echo "A@K@"												>> $CREATE_FILE 2>&1
  echo "@@@@"												>> $CREATE_FILE 2>&1
  
else
  echo "!@#$"													>> $CREATE_FILE 2>&1
  echo "K@A@"													>> $CREATE_FILE 2>&1
    echo "* Apache 서비스 미사용 중입니다."						>> $CREATE_FILE 2>&1 
  echo "A@K@"													>> $CREATE_FILE 2>&1
  echo "@@@@"													>> $CREATE_FILE 2>&1
fi 



echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $apache_service_online -eq 1 ]
  then
    if [ $is_conf -eq 0 ]; then
      echo "[1.08] 수동점검 - httpd.conf 파일을 찾을 수 없습니다."					>> $CREATE_FILE 2>&1
    elif [ $result_1_08 -eq 1 ]; then
      echo "[1.08] 양호"										>> $CREATE_FILE 2>&1
    elif [ $result_1_08 -eq 0 ]; then
      echo "[1.08] 취약"										>> $CREATE_FILE 2>&1  
    else
      :
    fi
  else
    echo "[1.08] 양호"											>> $CREATE_FILE 2>&1
fi



echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-08 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-08 END"
unset result_1_08
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-09 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-09 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                            1.09 Apache CGI 스크립트 실행 제한                         " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: ScriptAlias 에 지정된 디렉터리를 사용하지 않거나 게시판이나 업로드 디렉터리가 아니면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $apache_service_online -eq 1 ]
then


  echo "!@#$"											>> $CREATE_FILE 2>&1
  echo "K@A@"											>> $CREATE_FILE 2>&1


  result_1_09=1

  for httpd_conf in `cat PATH_HTTPD_CONF`;do
      echo "① $httpd_conf 파일에서 ScriptAlias 지시자 설정 확인"			>> $CREATE_FILE 2>&1
      echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	  if [ -f $httpd_conf ]
	    then
	      cat $httpd_conf | grep -i ScriptAlias | grep -v "\#"							>> $CREATE_FILE 2>&1
		  echo " "                                                                      >> $CREATE_FILE 2>&1
		  if [ `cat $httpd_conf | grep -i ScriptAlias | grep -v "\#" | wc -l` -eq 0 ]
		    then
		      echo "* ScriptAlias 설정이 되어 있지 않습니다."								>> $CREATE_FILE 2>&1
		    else
		      echo "* ScriptAlias 설정이 되어 있습니다."						>> $CREATE_FILE 2>&1
			  result_1_09=0
		  fi
	    else
	      echo "* $httpd_conf 파일이 없습니다."						>> $CREATE_FILE 2>&1 
	  fi
	  echo " "										>> $CREATE_FILE 2>&1
  done


  echo "A@K@"												>> $CREATE_FILE 2>&1
  echo "@@@@"												>> $CREATE_FILE 2>&1
  
else
  echo "!@#$"													>> $CREATE_FILE 2>&1
  echo "K@A@"													>> $CREATE_FILE 2>&1
    echo "* Apache 서비스 미사용 중입니다."						>> $CREATE_FILE 2>&1 
  echo "A@K@"													>> $CREATE_FILE 2>&1
  echo "@@@@"													>> $CREATE_FILE 2>&1
fi 



echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $apache_service_online -eq 1 ]
  then
    if [ $is_conf -eq 0 ]; then
      echo "[1.09] 수동점검 - httpd.conf 파일을 찾을 수 없습니다."					>> $CREATE_FILE 2>&1
    elif [ $result_1_09 -eq 1 ]; then
      echo "[1.09] 양호"										>> $CREATE_FILE 2>&1
    elif [ $result_1_09 -eq 0 ]; then
      echo "[1.09] 수동점검"										>> $CREATE_FILE 2>&1  
    else
      :
    fi
  else
    echo "[1.09] 양호"											>> $CREATE_FILE 2>&1
fi



echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-09 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-09 END"
unset result_1_09
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "




echo "U-10 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-10 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                            1.10 Apache 에러 메시지 관리                         		 " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 400,401,403,404,500 에러코드를 일관된 에러페이지로 지정하는 경우 양호" 		   >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $apache_service_online -eq 1 ]
then


  echo "!@#$"											>> $CREATE_FILE 2>&1
  echo "K@A@"											>> $CREATE_FILE 2>&1


  result_1_10=1

  for httpd_conf in `cat PATH_HTTPD_CONF`;do
      echo "① $httpd_conf 파일에서 ErrorDocument 지시자 설정 확인"			>> $CREATE_FILE 2>&1
      echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	  if [ -f $httpd_conf ]
	    then
	      cat $httpd_conf | grep -i ErrorDocument | grep -v "\#" 						>> $CREATE_FILE 2>&1
		  echo " "                                                                      >> $CREATE_FILE 2>&1
		  if [ \( `cat $httpd_conf |grep  -i ErrorDocument | grep 400 |grep -v "\#" | wc -l` -eq 0 \) \
			-a \( `cat $httpd_conf |grep  -i ErrorDocument | grep 403 |grep -v "\#" | wc -l` -eq 0 \) \
			-a \( `cat $httpd_conf |grep  -i ErrorDocument | grep 404 |grep -v "\#" | wc -l` -eq 0 \) \
			-a \( `cat $httpd_conf |grep  -i ErrorDocument | grep 500 |grep -v "\#" | wc -l` -eq 0 \) ];
		    then
		      echo "* ErrorDocument 설정이 되어 있지 않습니다."								>> $CREATE_FILE 2>&1
			  result_1_10=0
		    else
		      echo "* ErrorDocument 설정이 되어 있습니다."						>> $CREATE_FILE 2>&1
		  fi
	    else
	      echo "* $httpd_conf 파일이 없습니다."						>> $CREATE_FILE 2>&1 
	  fi
	  echo " "										>> $CREATE_FILE 2>&1
  done


  echo "A@K@"												>> $CREATE_FILE 2>&1
  echo "@@@@"												>> $CREATE_FILE 2>&1
  
else
  echo "!@#$"													>> $CREATE_FILE 2>&1
  echo "K@A@"													>> $CREATE_FILE 2>&1
    echo "* Apache 서비스 미사용 중입니다."						>> $CREATE_FILE 2>&1 
  echo "A@K@"													>> $CREATE_FILE 2>&1
  echo "@@@@"													>> $CREATE_FILE 2>&1
fi 



echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $apache_service_online -eq 1 ]
  then
    if [ $is_conf -eq 0 ]; then
      echo "[1.10] 수동점검 - httpd.conf 파일을 찾을 수 없습니다."					>> $CREATE_FILE 2>&1
    elif [ $result_1_10 -eq 1 ]; then
      echo "[1.10] 양호"										>> $CREATE_FILE 2>&1
    elif [ $result_1_10 -eq 0 ]; then
      echo "[1.10] 취약"										>> $CREATE_FILE 2>&1  
    else
      :
    fi
  else
    echo "[1.10] 양호"											>> $CREATE_FILE 2>&1
fi



echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-10 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-10 END"
unset result_1_10
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "





echo "U-11 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-11 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                            1.11 Apache HTTP Method 제한                         		 " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: <Directory>노드에 <Limit> 또는 <LimitExcept> 노드로 GET POST HEAD 메소드만 허용할 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $apache_service_online -eq 1 ]
then


  echo "!@#$"											>> $CREATE_FILE 2>&1
  echo "K@A@"											>> $CREATE_FILE 2>&1


  result_1_11=1

  for httpd_conf in `cat PATH_HTTPD_CONF`;do
      echo "① $httpd_conf 파일에서 Limit 또는 LimitExcept 설정 확인"			>> $CREATE_FILE 2>&1
      echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	  if [ -f $httpd_conf ]
	    then
	      cat $httpd_conf | grep Limit | grep -v ServerLimit | grep -v "\#" 			>> $CREATE_FILE 2>&1
		  echo " "                                                                      >> $CREATE_FILE 2>&1
		  if [ `cat  $httpd_conf | grep Limit | grep -v ServerLimit | grep -v "\#" | wc -l` -eq 0 ]
		    then
		      echo "* Limit 또는 LimitExcept 설정 확인 설정이 되어 있지 않습니다."								>> $CREATE_FILE 2>&1
			  result_1_11=0
		    else
		      echo "* Limit 또는 LimitExcept 설정 확인 설정이 되어 있습니다."						>> $CREATE_FILE 2>&1
		  fi
	    else
	      echo "* $httpd_conf 파일이 없습니다."						>> $CREATE_FILE 2>&1 
	  fi
	  echo " "										>> $CREATE_FILE 2>&1
  done


  echo "A@K@"												>> $CREATE_FILE 2>&1
  echo "@@@@"												>> $CREATE_FILE 2>&1
  
else
  echo "!@#$"													>> $CREATE_FILE 2>&1
  echo "K@A@"													>> $CREATE_FILE 2>&1
    echo "* Apache 서비스 미사용 중입니다."						>> $CREATE_FILE 2>&1 
  echo "A@K@"													>> $CREATE_FILE 2>&1
  echo "@@@@"													>> $CREATE_FILE 2>&1
fi 



echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $apache_service_online -eq 1 ]
  then
    if [ $is_conf -eq 0 ]; then
      echo "[1.11] 수동점검 - httpd.conf 파일을 찾을 수 없습니다."					>> $CREATE_FILE 2>&1
    elif [ $result_1_11 -eq 1 ]; then
      echo "[1.11] 수동점검"										>> $CREATE_FILE 2>&1
    elif [ $result_1_11 -eq 0 ]; then
      echo "[1.11] 취약"										>> $CREATE_FILE 2>&1  
    else
      :
    fi
  else
    echo "[1.11] 양호"											>> $CREATE_FILE 2>&1
fi



echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-11 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-11 END"
unset result_1_11
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "





echo "U-12 START"                                                                              >> $CREATE_FILE 2>&1
echo "U-12 START"
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "                            1.12 Apache 최신패치 적용                          		 " >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "■ 기준: 최신패치가 적용된 경우 양호" 													   >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

if [ $apache_service_online -eq 1 ]
then


  echo "!@#$"											>> $CREATE_FILE 2>&1
  echo "K@A@"											>> $CREATE_FILE 2>&1


  result_1_12=1

  for httpd_conf in `cat PATH_HTTPD_CONF`;do
      echo "① $httpd_conf 파일에서 Limit 또는 LimitExcept 설정 확인"			>> $CREATE_FILE 2>&1
      echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
	  if [ -f $httpd_conf ]
	    then
	      #DocumentRoot Path
		  docroot=`cat $httpd_conf | grep DocumentRoot |grep -v '\#'|awk -F'"' '{print $2}'`
		  #ServerRoot Path
		  svrroot=`cat $httpd_conf | grep ServerRoot |grep -v '\#'|awk -F'"' '{print $2}'`
		  svrroot=${svrroot:-"$apache"}


          if [ "$svrroot" = "/etc/httpd" -o "$svrroot" = "/etc/httpd/" ]; then
			httpd=/usr/sbin/httpd
		  else
			httpd="$svrroot"/bin/httpd
		  fi

		  if [ \( "$version" = "" \) ]; then
			version=`"$httpd" -v |grep version |awk -F' ' '{print $3}'`
			ver=`echo $version | awk -F'/' '{print $2}'`	
		  else
			ver=$version	
		  fi	

		  echo "Apache HTTP Version $version" 					>> $CREATE_FILE 2>&1
		  echo " "                                                                      >> $CREATE_FILE 2>&1
		  echo " "                                                                      >> $CREATE_FILE 2>&1

		  ver=${ver:-unknown}

		  ver1=`echo $ver | awk -F. '{print $1}'`
		  ver2=`echo $ver | awk -F. '{print $2}'`
		  ver3=`echo $ver | awk -F. '{print $3}'`
		  ver4=`echo $ver | awk -F. '{print $4}'`

		  if [ $ver1 -eq 2 ]; then
			if [ $ver3 -ge 64 ]; then
				result_1_12='Good'
			else
				result_1_12='Vulnerability'
			fi
		  else
			if [ $ver1 -eq 2 ]; then
				if [ $ver2 -eq 2 ]; then
					if [ $ver3 -ge 18 ]; then
						result_1_12='Good'
					else
						result_1_12='Vulnerability'
					fi
				else
					if [ $ver3 -ge 11 ]; then
						result_1_12='Good'
					else
						result_1_12='Vulnerability'
					fi
				fi
			else
				echo '버전 정보를 찾을 수 없음' >> $CREATE_FILE 2>&1
				result_1_12='N/A'
			fi
		  fi
		  echo ' ' >> $CREATE_FILE 2>&1
		  echo '[최신 버전 (2017.6 기준)]' >> $CREATE_FILE 2>&1
		  echo 'Apache 2.4.26' >> $CREATE_FILE 2>&1
		  echo 'Apache 2.2.32' >> $CREATE_FILE 2>&1
		  echo ' ' >> $CREATE_FILE 2>&1
	    else
	      echo "* $httpd_conf 파일이 없습니다."						>> $CREATE_FILE 2>&1 
	  fi
	  echo " "										>> $CREATE_FILE 2>&1
  done


  echo "A@K@"												>> $CREATE_FILE 2>&1
  echo "@@@@"												>> $CREATE_FILE 2>&1
  
else
  echo "!@#$"													>> $CREATE_FILE 2>&1
  echo "K@A@"													>> $CREATE_FILE 2>&1
    echo "* Apache 서비스 미사용 중입니다."						>> $CREATE_FILE 2>&1 
  echo "A@K@"													>> $CREATE_FILE 2>&1
  echo "@@@@"													>> $CREATE_FILE 2>&1
fi 



echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ $apache_service_online -eq 1 ]
  then
    if [ $is_conf -eq 0 ]; then
      echo "[1.12] 수동점검 - httpd.conf 파일을 찾을 수 없습니다."					>> $CREATE_FILE 2>&1
    elif [ $result_1_12 = 'Good' ]; then
      echo "[1.12] 수동점검"										>> $CREATE_FILE 2>&1
    elif [ $result_1_12 = 'Vulnerability' ]; then
      echo "[1.12] 취약"										    >> $CREATE_FILE 2>&1
	elif [ $result_1_12 = 'N/A' ]; then
      echo "[1.12] 수동점검"										>> $CREATE_FILE 2>&1	  
    else
      :
    fi
  else
    echo "[1.12] 양호"											>> $CREATE_FILE 2>&1
fi



echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-12 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo "U-12 END"
unset result_1_12
unset ver
unset ver1
unset ver2
unset ver3
unset ver4
unset version
unset svrroot
unset httpd
unset docroot
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "


rm -Rf PATH_HTTPD_CONF 2>&1
unset apache_service_online
unset is_conf
echo " "
echo " "
echo " "
echo " "


echo "* Kernel_Start " >> $CREATE_FILE 2>&1
echo "#######################################   Kernel Information   #########################################" >> $CREATE_FILE 2>&1
uname -a >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "* Kernel_End " >> $CREATE_FILE 2>&1

echo "* IP_Start " >> $CREATE_FILE 2>&1
echo "#########################################   IP Information   ###########################################" >> $CREATE_FILE 2>&1
ifconfig -a >> $CREATE_FILE 2>&1
echo "* IP_End " >> $CREATE_FILE 2>&1




echo "############################# End Time #######################################"
date
echo "############################# End Time #######################################" >> $CREATE_FILE 2>&1



 

