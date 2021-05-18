## pc 0 ~ 2

##< 패스워드 설정 기준 >
## 최소 암호 길이 8자 이상의 패스워드 설 pc 2
net accounts /MINPWLEN:8
## 90일 이후 설정
net accounts /maxpwage:90

##공유 폴더 설정 
net share

net share IPC$ /delete

net share ADMIN$ /delete

## 프로세스 점검 

sfc /scannow
net user lsh