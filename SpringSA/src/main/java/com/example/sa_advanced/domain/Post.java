package com.example.sa_advanced.domain;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
public class Post extends Timestamped {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name="member_id", nullable = false)
    private Member member;

    @OneToMany(mappedBy = "post")
    private List<Comment> comments = new ArrayList<>();

    @Column(nullable = false)
    private String title;

    @Column(nullable = false)
    private String imageUrl;

    @Column(nullable = false)
    private Integer likeCount;




}
