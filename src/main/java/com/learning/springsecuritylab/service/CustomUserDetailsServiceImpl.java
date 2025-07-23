package com.learning.springsecuritylab.service;

import com.learning.springsecuritylab.entity.Authority;
import com.learning.springsecuritylab.entity.UserEntity;
import com.learning.springsecuritylab.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;
    /**
     * @param username the username identifying the user whose data is required.
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntity = userRepository.findByUserName(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
        Set<Authority> authorities = userEntity.getAuthorities();
        List<GrantedAuthority> grantedAuthorities = authorities.stream().map(authority ->
                new SimpleGrantedAuthority(authority.getName())).collect(Collectors.toList());
        return new User(
                userEntity.getUserName(),
                userEntity.getPassword(),
                grantedAuthorities
        );
    }
}
