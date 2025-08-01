package com.learning.springsecuritylab.repository;

import com.learning.springsecuritylab.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Long> {
    UserEntity findByEmailId(String email);
    Optional<UserEntity> findByUserName(String username);
    Optional<UserEntity> findById(Long id);
}
