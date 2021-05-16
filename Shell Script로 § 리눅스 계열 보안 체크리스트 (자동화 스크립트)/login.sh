# !/bin/bash
# version 2.0
# author by 網菔務卐
cat <<EOF
*************************************************************************************
***** 설명 ：
***** 1. 원격 로그인 보안에 취약할 수 있으므로 su root 를 실행시킬 수 있음.
***** 2. 일반 사용자가 검사할 서버 /tmp 디렉토리에 읽기 쓰기 권한으로 업로드를 실행함.
***** 3. 검사할 서버 /tmp 디렉토리에 checklinux.sh 파일를 업로드 후 실행시킴.
***** 4. 결과 파일을 원격 서버로 가져옴.
***** 5. 자동으로 checklinux.sh 파일과 결과 파일을 삭제함.
*************************************************************************************
EOF
for i in `cat hosts.txt`
do
  # 원격 IP 주소
  ipadd=`echo $i | awk -F "[~]" '{print $1}'`
  # 사용자 계정명
  username=`echo $i | awk -F "[~]" '{print $2}'`
  # 사용자 계정 암호
  userpasswd=`echo $i | awk -F "[~]" '{print $3}'`
  # root 사용자 암호
  rootpasswd=`echo $i | awk -F "[~]" '{print $4}'`
  # checklinux.sh 파일을 검사할 서버에 업로드
  expect put.exp $ipadd $username $userpasswd 
  # checklinux.sh 실행
  expect sh.exp $ipadd $username $userpasswd $rootpasswd 
  # 결과 파일 가져옴
  expect get.exp $ipadd $username $userpasswd 
  # checklinux.sh 파일과 결과 파일을 삭제
  expect del.exp $ipadd $username $userpasswd $rootpasswd
done
