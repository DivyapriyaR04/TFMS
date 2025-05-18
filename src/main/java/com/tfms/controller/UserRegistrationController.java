package com.tfms.controller;

import com.tfms.model.User;
import com.tfms.service.UserService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.logging.Logger;

@Controller
@RequestMapping("/register")
public class UserRegistrationController {

    private static final Logger LOGGER = Logger.getLogger(UserRegistrationController.class.getName());
    private final UserService userService;

    public UserRegistrationController(UserService userService) {
        this.userService = userService;
    }

    // ✅ Display Registration Form
    @GetMapping
    public String showRegistrationForm(Model model) {
        model.addAttribute("user", new User());
        return "auth/register"; // ✅ Ensure Thymeleaf template exists
    }

    // ✅ Handle User Registration
    @PostMapping
    public String registerUser(@ModelAttribute("user") User user) {
        try {
            if (user.getFullName() == null || user.getFullName().isEmpty()) {
                throw new IllegalStateException("Full name is required!");
            }

            userService.registerUser(user);
            LOGGER.info("User registered successfully: " + user.getUsername());
            return "redirect:/login?success";
        } catch (IllegalStateException e) {
            LOGGER.warning("Registration failed: " + e.getMessage());
            return "redirect:/register?error";
        } catch (Exception e) {
            LOGGER.severe("Unexpected error during registration: " + e.getMessage());
            return "redirect:/register?error";
        }
    }

}
