package com.tfms.service.impl;

import com.tfms.model.Role;
import com.tfms.model.User;
import com.tfms.repository.RoleRepository;
import com.tfms.repository.UserRepository;
import com.tfms.service.UserService;
import org.springframework.security.core.userdetails.*;
import org.hibernate.validator.internal.util.stereotypes.Lazy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional; // Import this annotation

import javax.persistence.EntityNotFoundException;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService, UserDetailsService {

    private static final Logger LOGGER = Logger.getLogger(UserServiceImpl.class.getName());

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    @Autowired
    @Lazy
    private PasswordEncoder passwordEncoder; // Field injection

    @Autowired
    public UserServiceImpl(UserRepository userRepository, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @Override
    @Transactional
    public User registerUser(User user) {
        validateUserCredentials(user);

        user.setPassword(passwordEncoder.encode(user.getPassword()));

        // Ensures 'USER' role exists in DB before assigning
        Role userRole = roleRepository.findByName("USER").orElseGet(() -> {
            Role newRole = new Role();
            newRole.setName("USER");
            Role savedRole = roleRepository.save(newRole); // Persist new role in DB
            LOGGER.info("New role 'USER' created and saved.");
            return savedRole;
        });
        user.setRoles(Collections.singleton(userRole));

        LOGGER.info("Attempting to save user: " + user.getUsername());
        User savedUser = userRepository.save(user);

        if (savedUser == null || savedUser.getId() == null) {
            LOGGER.severe("User registration failed: Data was not persisted.");
            throw new IllegalStateException("User could not be saved in the database!");
        }

        LOGGER.info("User successfully saved with ID: " + savedUser.getId());
        return savedUser;
    }

    private void validateUserCredentials(User user) {
        if (userRepository.existsByUsername(user.getUsername())) {
            LOGGER.warning("Attempted registration with existing username: " + user.getUsername());
            throw new IllegalStateException("Username already exists: " + user.getUsername());
        }
        if (userRepository.existsByEmail(user.getEmail())) {
            LOGGER.warning("Attempted registration with existing email: " + user.getEmail());
            throw new IllegalStateException("Email already exists: " + user.getEmail());
        }
    }

    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public User getUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> {
                    LOGGER.warning("User not found with ID: " + id);
                    return new EntityNotFoundException("User not found with ID: " + id);
                });
    }

    @Override
    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    LOGGER.warning("User not found with username: " + username);
                    return new EntityNotFoundException("User not found with username: " + username);
                });
    }

    @Override
    @Transactional // Added this annotation
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        LOGGER.info("Attempting login for username: " + username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    LOGGER.warning("Authentication failed: User not found - " + username);
                    return new UsernameNotFoundException("User not found: " + username);
                });

        LOGGER.info("User found: " + user.getUsername() + ", Hashed Password: " + user.getPassword());

        // Debug password validation before authentication
        String rawPassword = "yourActualPassword"; // Replace with real input during testing
        if (passwordEncoder.matches(rawPassword, user.getPassword())) {
            LOGGER.info("Password matches for user: " + username);
        } else {
            LOGGER.warning("Invalid password for user: " + username);
        }

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.isEnabled(),
                true, true, true,
                user.getRoles().stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                        .collect(Collectors.toList())
        );
    }

    @Override
    @Transactional
    public User createUser(User user) {
        validateUserCredentials(user);
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        Role userRole = roleRepository.findByName("USER").orElseGet(() -> {
            Role newRole = new Role();
            newRole.setName("USER");
            return roleRepository.save(newRole);
        });
        user.setRoles(Collections.singleton(userRole));

        return userRepository.save(user);
    }

    @Override
    @Transactional
    public User updateUser(Long id, User userDetails) {
        User user = getUserById(id);
        user.setUsername(userDetails.getUsername());
        user.setEmail(userDetails.getEmail());
        user.setFullName(userDetails.getFullName());

        return userRepository.save(user);
    }

    @Override
    @Transactional
    public void deleteUser(Long id) {
        User user = getUserById(id);
        userRepository.delete(user);
        LOGGER.info("Deleted user with ID: " + id);
    }

    @Override
    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    @Override
    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }
}