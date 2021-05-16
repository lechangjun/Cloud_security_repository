#!/bin/sh

alias ls=ls
alias grep=/bin/grep

if [ -f /usr/ucb/echo ]
   then
      alias echo=/usr/ucb/echo
fi

_HOSTNAME=`/bin/hostname`
_PWD=`/bin/pwd`

mkdir $_PWD/tmp
_TMP_DIR=$_PWD/tmp

# Oracle 진단 스크립트 실행
echo ""
echo "################# Oracle Vulnerability Checker ###################"
echo ""
echo ""
echo "[ORACLE Home]"
echo $ORACLE_HOME 
echo ""
echo ""
echo ""
echo " > Oracle Home directory. "
while true
do 
   echo -n "    (ex. /usr/local/oracle/product/9.2.0) : " 
   read _ORA_HOME 
   if [ $_ORA_HOME ]
      then
         if [ -d $_ORA_HOME/network ]
            then 
               break
            else
               echo "   Re Try."
               echo " "
         fi
      else
         echo "   Wrong Path. Re Try."
         echo " "
   fi
done
echo " "
echo $_ORA_HOME > $_TMP_DIR/ora_home_dir.txt

# end script
