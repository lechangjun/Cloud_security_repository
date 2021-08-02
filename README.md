# ISMS_repository(인프라 보안)

  Linux 서버 취약점 점검 스크립트 자료

#### ⚒️ 취약점 점검 스크립트 자료 

       주요정보통신시설기반 리눅스 서버 기술적 취약점 분석 평가 상세 가이드에 기재된 

       모든 평가 항목에 대한 점검 스크립트 프로그램이 제작 됨 
       
       
####  - 💻 ISMS (KISA 한국인터넷진흥원) 


#### - 📋 참고 사항
##### - 🏠 위험도 구분


#####
```json
1. 상

      시스템, 서비스, 장비에 직접적인 위협을 초래할 수 있는 단계로
      장비의 관리자 권한을 탈취 당하거나 장비의 중요한 정보를 유출당할 위협이 있다.
2. 중

      시스템, 서비스, 장비에 직접 또는 간접적인 위협의 가능성이 있는 단계로
      접근 경로를 제공 하거나 정보 유출의 가능성을 높일 수 있는 단계
3. 하

      시스템 및 장비에 큰 영향을 주지 못하나 주의가 필요한 단계
```

\
[]()


📋 보고서 작성 요령

- [목차](https://github.com/lechangjun/ISMS_security_repository/blob/main/%E1%84%8C%E1%85%A5%E1%86%BC%E1%84%87%E1%85%A9%E1%84%87%E1%85%A9%E1%84%8B%E1%85%A1%E1%86%AB_%E1%84%86%E1%85%AE%E1%86%AB%E1%84%89%E1%85%A5%E1%84%8C%E1%85%A1%E1%86%A8%E1%84%8B%E1%85%A5%E1%86%B8/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C_.png/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C__2.png) 

- [시작](https://github.com/lechangjun/ISMS_security_repository/blob/main/%E1%84%8C%E1%85%A5%E1%86%BC%E1%84%87%E1%85%A9%E1%84%87%E1%85%A9%E1%84%8B%E1%85%A1%E1%86%AB_%E1%84%86%E1%85%AE%E1%86%AB%E1%84%89%E1%85%A5%E1%84%8C%E1%85%A1%E1%86%A8%E1%84%8B%E1%85%A5%E1%86%B8/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C_.png/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C__1.png)
- [중간](https://github.com/lechangjun/ISMS_security_repository/blob/main/%E1%84%8C%E1%85%A5%E1%86%BC%E1%84%87%E1%85%A9%E1%84%87%E1%85%A9%E1%84%8B%E1%85%A1%E1%86%AB_%E1%84%86%E1%85%AE%E1%86%AB%E1%84%89%E1%85%A5%E1%84%8C%E1%85%A1%E1%86%A8%E1%84%8B%E1%85%A5%E1%86%B8/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C_.png/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C__9.png)

     [1) 위협 분석 유형](https://github.com/lechangjun/ISMS_security_repository/blob/main/%E1%84%8C%E1%85%A5%E1%86%BC%E1%84%87%E1%85%A9%E1%84%87%E1%85%A9%E1%84%8B%E1%85%A1%E1%86%AB_%E1%84%86%E1%85%AE%E1%86%AB%E1%84%89%E1%85%A5%E1%84%8C%E1%85%A1%E1%86%A8%E1%84%8B%E1%85%A5%E1%86%B8/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C_.png/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C__15.png)
     
     
     [2) 취약점 분석 결과](https://github.com/lechangjun/ISMS_security_repository/blob/main/%E1%84%8C%E1%85%A5%E1%86%BC%E1%84%87%E1%85%A9%E1%84%87%E1%85%A9%E1%84%8B%E1%85%A1%E1%86%AB_%E1%84%86%E1%85%AE%E1%86%AB%E1%84%89%E1%85%A5%E1%84%8C%E1%85%A1%E1%86%A8%E1%84%8B%E1%85%A5%E1%86%B8/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C_.png/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C__23.png)



- [마무리](https://github.com/lechangjun/ISMS_security_repository/blob/main/%E1%84%8C%E1%85%A5%E1%86%BC%E1%84%87%E1%85%A9%E1%84%87%E1%85%A9%E1%84%8B%E1%85%A1%E1%86%AB_%E1%84%86%E1%85%AE%E1%86%AB%E1%84%89%E1%85%A5%E1%84%8C%E1%85%A1%E1%86%A8%E1%84%8B%E1%85%A5%E1%86%B8/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C_.png/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C__27.png)



     [2) 취약점 분석 결과](https://github.com/lechangjun/ISMS_security_repository/blob/main/%E1%84%8C%E1%85%A5%E1%86%BC%E1%84%87%E1%85%A9%E1%84%87%E1%85%A9%E1%84%8B%E1%85%A1%E1%86%AB_%E1%84%86%E1%85%AE%E1%86%AB%E1%84%89%E1%85%A5%E1%84%8C%E1%85%A1%E1%86%A8%E1%84%8B%E1%85%A5%E1%86%B8/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C_.png/(%EC%A0%9C%EB%8B%88%ED%8D%BC)%EC%9C%84%ED%97%98%EB%B6%84%EC%84%9D_%EB%B3%B4%EA%B3%A0%EC%84%9C__23.png)


참고 링크

#### http://www.freebuf.com/sectool/123094.html


#### https://www.kisa.or.kr/public/laws/laws3.jsp
