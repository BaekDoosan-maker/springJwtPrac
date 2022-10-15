package com.example.sa_advanced.domain;

import lombok.*;

import javax.persistence.*;
import java.sql.Time;


@Builder
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Member extends Timestamped {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String nickname;

    @Column(nullable = false)
    private String email;


}
