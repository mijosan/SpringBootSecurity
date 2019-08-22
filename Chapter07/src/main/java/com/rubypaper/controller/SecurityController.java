package com.rubypaper.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SecurityController {
	
	@GetMapping("/")
	public String index() {
		System.out.println("index ��û�Դϴ�.");
		return "index";
	}
	
	@GetMapping("/member")
	public void forMember() {
		System.out.println("Member ��û�Դϴ�.");
	}
	
	@GetMapping("/manager")
	public void forManager() {
		System.out.println("Manager ��û�Դϴ�.");
	}
	
	@GetMapping("/admin")
	public void forAdmin() {
		System.out.println("Admin ��û�Դϴ�.");
	}
	
	@GetMapping("/login")
	public void login() {
		
	}
	
	@GetMapping("/loginSuccess")
	public void loginSuccess() {
		
	}
	
	@GetMapping("/accessDenied")
	public void accessDenied() {
		
	}
	
	
}
