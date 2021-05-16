# !/bin/bash
# version 2.0
# author by 網菔務卐

cat <<EOF
*************************************************************************************
*****
***** 리눅스 계열 체크리스트
***** 결과 파일은 /tmp/${ipadd}_out.txt 형식을 저장
*****
*************************************************************************************
EOF

echo "***************************"
echo "*** 계정정책 확인"
echo "***************************"
ipadd=`ifconfig -a | grep Bcast | awk -F "[ :]+" '{print $4}'`
passmax=`cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^# | awk '{print $2}'`
passmin=`cat /etc/login.defs | grep PASS_MIN_DAYS | grep -v ^# | awk '{print $2}'`
passlen=`cat /etc/login.defs | grep PASS_MIN_LEN | grep -v ^# | awk '{print $2}'`
passage=`cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^# | awk '{print $2}'`

if [ $passmax -le 90 -a $passmax -gt 0];then
  echo "${passmax} 일 - 암호 수명 정상" >> /tmp/${ipadd}_out.txt
else
  echo "${passmax} 일 - 암호 수명 취약 (90 일 설정)" >> /tmp/${ipadd}_out.txt
fi

if [ $passmin -ge 6 ];then
  echo "${passmin} 일 - 최소 암호 변경 간격 정상" >> /tmp/${ipadd}_out.txt
else
  echo "${passmin} 일 - 최소 암호 변경 간격 취약 (6일 이상 설정)" >> /tmp/${ipadd}_out.txt
fi

if [ $passlen -ge 8 ];then
  echo "${passlen} 자리 - 최소 암호 길이 정상" >> /tmp/${ipadd}_out.txt
else
  echo "${passlen} 자리 - 최소 암호 길이 취약 (8자리 이상 설정)" >> /tmp/${ipadd}_out.txt
fi

if [ $passage -ge 30 -a $passage -lt $passmax ];then
  echo "${passage} 시간 - 암호 만료 경고일 정상" >> /tmp/${ipadd}_out.txt
else
  echo "${passage} 시간 - 암호 만료 경고일 취약 (30일 설정)" >> /tmp/${ipadd}_out.txt
fi

echo "***************************"
echo "*** 검사 도중 터미널 타임아웃이 될 수 있음!!!"
echo "***************************"
cat /etc/profile | grep TMOUT | awk -F[=] '{print $2}' 
if [ $? -eq 0 ];then
  TMOUT=`cat /etc/profile | grep TMOUT | awk -F[=] '{print $2}'`
  if [ $TMOUT -le 600 -a $TMOUT -ge 10 ];then
    echo "${TMOUT} 초 - 터미널 타임아웃 정상" >> /tmp/${ipadd}_out.txt
  else
    echo "${TMOUT} 초 - 터미널 타임아웃 취약 (600 초 미만 권장 설정)" >> /tmp/${ipadd}_out.txt
  fi
else
  echo "터미널 타임아웃 비설정 (600 초 미만 권장 설정)" >> /tmp/${ipadd}_out.txt 
fi

# grub와 lilo 암호 설정 확인
cat /etc/grub.conf | grep password 2> /dev/null
if [ $? -eq 0 ];then
  echo "grub 암호 설정 - 정상" >> /tmp/${ipadd}_out.txt
else
  echo "grup 암호 비설정 - 취약" >> /tmp/${ipadd}_out.txt
fi

cat /etc/lilo.conf | grep password 2> /dev/null
if [ $? -eq 0 ];then
  echo "lilo 암호 설정 - 정상" >> /tmp/${ipadd}_out.txt
else
  echo "lilo 암호 비설정 - 취약" >> /tmp/${ipadd}_out.txt
fi

# 비 root 계정 중에서 UID 0 찾기
UIDS=`awk -F[:] 'NR!=1{print $3}' /etc/passwd`
flag=0
for i in $UIDS
do
  if [ $i = 0 ];then
    echo "비 root 계정 중에서 UID 0 존재 - 취약" >> /tmp/${ipadd}_out.txt
  else
    flag=1
  fi
done
if [ $flag = 1 ];then
  echo "비 root 계정 중에서 UID 0 존재하지 않음 - 정상" >> /tmp/${ipadd}_out.txt
fi

# umask 설정 확인
umask1=`cat /etc/profile | grep umask | grep -v ^# | awk '{print $2}'`
umask2=`cat /etc/csh.cshrc | grep umask | grep -v ^# | awk '{print $2}'`
umask3=`cat /etc/bashrc | grep umask | grep -v ^# | awk 'NR!=1{print $2}'`
flags=0
for i in $umask1
do
  if [ $i = "027" ];then
    echo "${i} - /etc/profile 파일의 umask 설정 정상" >> /tmp/${ipadd}_out.txt
  else
    flags=1
  fi
done
if [ $flags = 1 ];then
  echo "${i} - /etc/profile 파일의 umask 설정 취약 (027 설정)" >> /tmp/${ipadd}_out.txt
fi 


flags=0
for i in $umask2
do
  if [ $i = "027" ];then
    echo "${i} - /etc/csh.cshrc 파일의 umask 설정 정상" >> /tmp/${ipadd}_out.txt
  else
    flags=1
  fi
done  
if [ $flags = 1 ];then
  echo "${i} - /etc/csh.cshrc 파일의 umask 설정 취약 (027 설정)" >> /tmp/${ipadd}_out.txt
fi


flags=0
for i in $umask3
do
  if [ $i = "027" ];then
    echo "${i} - /etc/bashrc 파일의 umask 설정 정상" >> /tmp/${ipadd}_out.txt
  else
    flags=1
  fi
done
if [ $flags = 1 ];then
  echo "${i} - /etc/bashrc 파일의 umask 설정 취약 (027 설정)" >> /tmp/${ipadd}_out.txt
fi

echo "***************************"
echo "*** 중요한 파일 권한 확인"
echo "***************************"

file1=`ls -l /etc/passwd | awk '{print $1}'`
file2=`ls -l /etc/shadow | awk '{print $1}'`
file3=`ls -l /etc/group | awk '{print $1}'`
file4=`ls -l /etc/securetty | awk '{print $1}'`
file5=`ls -l /etc/services | awk '{print $1}'`
file6=`ls -l /etc/xinetd.conf | awk '{print $1}'`
file7=`ls -l /etc/grub.conf | awk '{print $1}'`
file8=`ls -l /etc/lilo.conf | awk '{print $1}'`

if [ $file1 = "-rw-r--r--" ];then
  echo "/etc/passwd 파일권한 정상" >> /tmp/${ipadd}_out.txt
else
  echo "/etc/passwd 파일권한 취약 (644 설정)" >> /tmp/${ipadd}_out.txt
fi

if [ $file2 = "-r--------" ];then
  echo "/etc/shadow 파일권한 정상" >> /tmp/${ipadd}_out.txt
else
  echo "/etc/shadow 파일권한 취약 (400 설정)" >> /tmp/${ipadd}_out.txt
fi

if [ $file3 = "-rw-r--r--" ];then
  echo "/etc/group 파일권한 정상" >> /tmp/${ipadd}_out.txt
else
  echo "/etc/group 파일권한 취약 (644 설정)" >> /tmp/${ipadd}_out.txt
fi

if [ $file4 = "-rw-------" ];then
  echo "/etc/security 파일권한 정상" >> /tmp/${ipadd}_out.txt
else
  echo "/etc/security 파일권한 취약 (600 설정)" >> /tmp/${ipadd}_out.txt
fi

if [ $file5 = "-rw-r--r--" ];then
  echo "/etc/services 파일권한 정상" >> /tmp/${ipadd}_out.txt
else
  echo "/etc/services 파일권한 취약 (644 설정)" >> /tmp/${ipadd}_out.txt
fi

if [ $file6 = "-rw-------" ];then
  echo "/etc/xinetd.conf 파일권한 정상" >> /tmp/${ipadd}_out.txt
else
  echo "/etc/xinetd.conf 파일권한 취약 (600 설정)" >> /tmp/${ipadd}_out.txt
fi

if [ $file7 = "-rw-------" ];then
  echo "/etc/grub.conf 파일권한 정상" >> /tmp/${ipadd}_out.txt
else
  echo "/etc/grub.conf 파일권한 취약 (600 설정)" >> /tmp/${ipadd}_out.txt
fi

if [ -f /etc/lilo.conf ];then
  if [ $file8 = "-rw-------" ];then
    echo "/etc/lilo.conf 파일권한 정상" >> /tmp/${ipadd}_out.txt
  else
    echo "/etc/lilo.conf 파일권한 취약 (600 설정)" >> /tmp/${ipadd}_out.txt
  fi
  
else
  echo "/etc/lilo.conf 폴더가 존재하지 않음."
fi

cat /etc/security/limits.conf | grep -V ^# | grep core
if [ $? -eq 0 ];then
  soft=`cat /etc/security/limits.conf | grep -V ^# | grep core | awk {print $2}`
  for i in $soft
  do
    if [ $i = "soft" ];then
      echo "* soft core 0 설정" >> /tmp/${ipadd}_out.txt
    fi
    if [ $i = "hard" ];then
      echo "* hard core 0 설정" >> /tmp/${ipadd}_out.txt
    fi
  done
else 
  echo "core 설정이 되어 있지 않음. /etc/security/limits.conf 파일에 * soft core 0 과 * hard core 0 설정을 권장함." >> /tmp/${ipadd}_out.txt
fi

echo "***************************"
echo "*** ssh 파일 설정 확인"
echo "***************************"
cat /etc/ssh/sshd_config | grep -v ^# |grep "PermitRootLogin no"
if [ $? -eq 0 ];then
  echo "root 계정 원격 로그인 비허용 - 정상" >> /tmp/${ipadd}_out.txt
else
  echo "root 계정 원격 로그인 허용 - 취약 (/etc/ssh/sshd_config 파일에 PermitRootLogin no 설정" >> /tmp/${ipadd}_out.txt
fi

# telnet 서비스 활성화 확인
telnetd=`cat /etc/xinetd.d/telnet | grep disable | awk '{print $3}'`
if [ $telnetd = "yes" ];then
  echo "telnet 서비스 활성화 (텔넷 서비스 해제 권장)" >> /tmp/${ipadd}_out.txt
fi

Protocol=`cat /etc/ssh/sshd_config | grep -v ^# | grep Protocol | awk '{print $2}'`
if [ $Protocol = 2 ];then
  echo "openssh ssh2 프로토콜 사용 - 정상" >> /tmp/${ipadd}_out.txt
fi
if [ $Protocol = 1 ];then
  echo "openssh ssh1 프로토콜 사용 - 취약" >> /tmp/${ipadd}_out.txt
fi

# 명령어 재사용 버퍼 사이즈 확인
HISTSIZE=`cat /etc/profile|grep HISTSIZE|head -1|awk -F[=] '{print $2}'`
if [ $HISTSIZE -eq 5 ];then
  echo "$HISTSIZE - 정상" >> /tmp/${ipadd}_out.txt
else
  echo "$HISTSIZE - 취약 (/etc/profile 파일에 HISTSIZE 5 설정" >> /tmp/${ipadd}_out.txt
fi

# 중요한 파일 속성 확인
flag=0
for ((x=1;x<=15;x++))
do
  apend=`lsattr /etc/passwd | cut -c $x`
  if [ $apend = "i" ];then
    echo "/etc/passwd 파일 속성 i 확인" >> /tmp/${ipadd}_out.txt
    flag=1
  fi
  if [ $apend = "a" ];then
    echo "/etc/passwd 파일 속성 a 확인" >> /tmp/${ipadd}_out.txt
    flag=1
  fi
done
if [ $flag = 0 ];then
  echo "/etc/passwd 파일 속성이 존재하지 않음. - 취약 (/etc/passwd 파일이 수정 및 삭제를 방지하기 위해 chattr +i 또는 chattr +a 설정)" >> /tmp/${ipadd}_out.txt
fi

flag=0
for ((x=1;x<=15;x++))
do
  apend=`lsattr /etc/shadow | cut -c $x`
  if [ $apend = "i" ];then
    echo "/etc/shadow 파일 속성 i 확인" >> /tmp/${ipadd}_out.txt
    flag=1
  fi
  if [ $apend = "a" ];then
    echo "/etc/shadow 파일 속성 a 확인" >> /tmp/${ipadd}_out.txt
    flag=1
  fi
done
if [ $flag = 0 ];then
  echo "/etc/shadow 파일 속성이 존재하지 않음. - 취약 (/etc/shadow 파일이 수정 및 삭제를 방지하기 위해 chattr +i 또는 chattr +a 설정)" >> /tmp/${ipadd}_out.txt
fi

flag=0
for ((x=1;x<=15;x++))
do
  apend=`lsattr /etc/gshadow | cut -c $x`
  if [ $apend = "i" ];then
    echo "/etc/gshadow 파일 속성 i 확인" >> /tmp/${ipadd}_out.txt
    flag=1
  fi
  if [ $apend = "a" ];then
    echo "/etc/gshadow 파일 속성 a 확인" >> /tmp/${ipadd}_out.txt
    flag=1
  fi
done
if [ $flag = 0 ];then
  echo "/etc/gshadow 파일 속성이 존재하지 않음. - 취약 (/etc/gshadow 파일이 수정 및 삭제를 방지하기 위해 chattr +i 또는 chattr +a 설정" >> /tmp/${ipadd}_out.txt
fi

flag=0
for ((x=1;x<=15;x++))
do
  apend=`lsattr /etc/group | cut -c $x`
  if [ $apend = "i" ];then
    echo "/etc/group 파일 속성 i 확인" >> /tmp/${ipadd}_out.txt
    flag=1
  fi
  if [ $apend = "a" ];then
    echo "/etc/group 파일 속성 a 확인" >> /tmp/${ipadd}_out.txt
    flag=1
  fi
done
if [ $flag = 0 ];then
  echo "/etc/group 파일 속성이 존재하지 않음. - 취약 (/etc/group 파일이 수정 및 삭제를 방지하기 위해 chattr +i 또는 chattr +a 설정" >> /tmp/${ipadd}_out.txt
fi

# SNMP Community String 디폴트명 확인 (public, private)
if [ -f /etc/snmp/snmpd.conf ];then
  public=`cat /etc/snmp/snmpd.conf | grep public | grep -v ^# | awk '{print $4}'`
  private=`cat /etc/snmp/snmpd.conf | grep private | grep -v ^# | awk '{print $4}'`
  if [ $public = "public" ];then
    echo "SNMP Community String 디폴트명 public - 취약" >> /tmp/${ipadd}_out.txt
  fi
  if [[ $private = "private" ]];then
    echo "SNMP Community String 디폴트명 private - 취약" >> /tmp/${ipadd}_out.txt
  fi
else
  echo "snmp 서비스 설정 파일이 존재하지 않음." 
fi

# 원격 시스템에 대해 신뢰할 수 있는 호스트 목록 확인
rhosts=`find / -name .rhosts`
rhosts2=`find / -name hosts.equiv`
for i in $rhosts
do
  if [ -f $i ];then
  echo "${i} - 신뢰할 수 있는 호스트인지 확인 바람." >> /tmp/${ipadd}_out.txt
  fi 
done

# auditd 서비스 활성화 확인 (리눅스 감사 시스템 데몬)
service auditd status
if [ $? = 0 ];then
  echo "auditd 서비스 활성화 - 정상" >> /tmp/${ipadd}_out.txt
fi
if [ $? = 3 ];then
  echo "auditd 서비스 비활성화 - 취약 (service auditd start 명령어 실행)" >> /tmp/${ipadd}_out.txt
fi

# 디스크 저장 용량 80% 이상여부 확인
space=`df -h | awk -F "[ %]+" 'NR!=1{print $5}'`
for i in $space
do
  if [ $i -ge 80 ];then
    echo "경고! 디스크 저장 용량이 80 % 를 초과함. 불필요한 파일 삭제 바람!" >> /tmp/${ipadd}_out.txt
  fi
done

echo "***************************"
echo "*** 검사 완료"
echo "***************************"
