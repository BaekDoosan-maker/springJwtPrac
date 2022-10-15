package com.example.sa_advanced.domain;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;


@Data
@AllArgsConstructor
@Entity
@NoArgsConstructor
public class Comment extends Timestamped{

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long commmentId;

    @ManyToOne
    @JoinColumn(name="member_id", nullable = false)
    private Member member;

    @ManyToOne
    @JoinColumn(name="post_id", nullable = false)
    private Post post;

    @Column(nullable = false)
    private String content;

    @Column(nullable = false)
    private Integer like_count;
}
