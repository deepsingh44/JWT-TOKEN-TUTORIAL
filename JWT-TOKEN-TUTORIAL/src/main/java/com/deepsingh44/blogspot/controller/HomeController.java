package com.deepsingh44.blogspot.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.deepsingh44.blogspot.model.JwtRequest;
import com.deepsingh44.blogspot.model.JwtResponse;
import com.deepsingh44.blogspot.model.User;
import com.deepsingh44.blogspot.repository.UserRepository;
import com.deepsingh44.blogspot.service.CustomUserDetailService;
import com.deepsingh44.blogspot.util.JwtUtility;

@RestController
public class HomeController {
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private PasswordEncoder encoder;
	@Autowired
	private CustomUserDetailService customUserDetailService;
	@Autowired
	private JwtUtility jwtUtility;
	@Autowired
	private AuthenticationManager authenticationManager;

	@PostMapping("/register")
	public ResponseEntity<?> saveUser(@RequestBody User user) throws Exception {
		String encpass = encoder.encode(user.getPassword());
		user.setPassword(encpass);
		return ResponseEntity.ok(userRepository.save(user));
	}

	@GetMapping("/home")
	public String home() {
		return "Welcome to home page";
	}

	@PostMapping("/authenticate")
	public ResponseEntity<?> authenticate(@RequestBody JwtRequest jwtRequest) throws Exception {
		try {
			authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(jwtRequest.getUsername(), jwtRequest.getPassword()));
		} catch (DisabledException disabledException) {
			throw new Exception("USER_IS_DISABLE", disabledException);
		} catch (BadCredentialsException badCredentialsException) {
			throw new Exception("INVALID_USER_CREDENTIALS", badCredentialsException);
		}
		final UserDetails userDetails = customUserDetailService.loadUserByUsername(jwtRequest.getUsername());
		final String token = jwtUtility.generateToken(userDetails);
		return ResponseEntity.ok(new JwtResponse(token));
	}

}
