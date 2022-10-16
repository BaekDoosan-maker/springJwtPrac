package com.example.sa_advanced.domain;

import lombok.*;
import org.hibernate.Hibernate;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.persistence.*;
import java.sql.Time;
import java.util.Objects;


@Builder // private 생성자를 가지는 클래스 Builder라는 이름의 내부 빌더 클래스를 생성하여 빌더패턴을 구현한다. 빌더 클래스를 생성하고자 하는 클래스 외부에서 빌더 인스턴스를 만들어서 사용할 이유는 없기 때문에 private 생성자로 접근을 차단한다.
@Getter // Lombok 어노테이션으로, 클래스 레벨에 @Getter를 선언해줄경우, 모든 필드에 접근자와 설정자가 자동으로 생성된다.
@NoArgsConstructor
@AllArgsConstructor // Lombok 어노테이션으로, 모든 필드 값을 파라미터로 받는 생성자를 만들어 준다.
@Entity
public class Member extends Timestamped { // Timestamped 상속
    // 기본키 생성 및 제약조건과 @GeneratedValue
    @Id    // 기본 키 매핑  * GenerationType.IDENTITY 전략은?  id 값을 설정하지 않고 (null) INSERT Query를 날리면 그 때 id의 값을 세팅한다.
    @GeneratedValue(strategy = GenerationType.IDENTITY) // GeneratedValue(starategy = GenerationType.IDENTITY ) ->
    private Long id;           // @GeneratedValue 자동 생성 전략 : IDENTITY 개념 @GenertedValue(strategy = GenerationType.IDENTITY) 기본 키 생성을 데이터 베이스에 위임 -> id값을 null로 하면 DB가 알아서 AUITO_INCREMENT 해준다. Ex) MySQL

    @Column(nullable = false) // @Column(nullable = false) null값 인정
    private String password;

    @Column(nullable = false) // @Column(nullable = false) null값 인정
    private String nickname;

    @Column(nullable = false) // @Column(nullable = false) null값 인정
    private String email;

    @Override
    public boolean equals(Object object) {
        if(this == object) {
            return true;
        }

        if(object == null || Hibernate.getClass(this) != Hibernate.getClass(object)) {
            return false;

        }
        Member member = (Member) object;
        return id != null && Objects.equals(id, member.id);
    }

    @Override
    public int hashCode(){  // 자바 빈을 만들때 hashCode 메소드를 오버라이딩 한다.
        return getClass().hashCode();

    }

    /**
     * password Endcoder : 비밀번호 유효성 검사 -> 인코딩한 passsword가 유저의 password와 매칭되면 passwordEncoder로 파라미터값 ( password, this.password)을 리턴시킨다.
     * @param passwordEncoder
     * @param password
     * @return
     */
    public boolean validatePassword(PasswordEncoder passwordEncoder, String password) {
        return passwordEncoder.matches(password, this.password);
    }
}
