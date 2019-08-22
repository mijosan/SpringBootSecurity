package com.rubypaper.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity //이 클래스로부터 생성된 객체가 시큐리티 설정 파일임을 의미, 동시에 시큐리티를 사용하는데 필요한 수많은 객체를 생성한다.
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Autowired
	private BoardUserDetailsService boardUserDetailsService;
	
	
	/*
	 * @Autowired private DataSource dataSource;
	 */
	
	@Override
	protected void configure(HttpSecurity security) throws Exception{
		security.authorizeRequests().antMatchers("/").permitAll(); //모든 사용자에게 접근 허용
		security.authorizeRequests().antMatchers("/member/**").authenticated(); //인증된 사용자만 접근허용
		security.authorizeRequests().antMatchers("/manager/**").hasRole("MANAGER"); //hasRole("권한")은 특정 권한을 가진 사용자만 접근 허용
		security.authorizeRequests().antMatchers("/admin/**").hasRole("ADMIN");
		
		security.csrf().disable();
		security.formLogin().loginPage("/login").defaultSuccessUrl("/loginSuccess", true); //사용자에게 로그인 화면을 제공
		security.exceptionHandling().accessDeniedPage("/accessDenied");
		security.logout().invalidateHttpSession(true).logoutSuccessUrl("/login");
		
		security.userDetailsService(boardUserDetailsService);
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
	
	/*
	 * @Autowired public void authenticate(AuthenticationManagerBuilder auth) throws
	 * Exception { String query1 =
	 * "select id as username, password from member where id=?";
	 * 
	 * String query2 = "select id, role from member where id=?";
	 * 
	 * auth.jdbcAuthentication() .dataSource(dataSource)
	 * .usersByUsernameQuery(query1) .authoritiesByUsernameQuery(query2); }
	 */
	/*
	 * @Autowired//매개변수 의존성 주입 public void authenticate(AuthenticationManagerBuilder
	 * auth) throws Exception{//메모리에 사용자 정보를 간단하게 생성할려고 만듬
	 * auth.inMemoryAuthentication() //메모리에 사용자 정보를 생성하는 메소드 .withUser("manager")
	 * //생성될 사용자의 아이디 .password("{noop}manager123") //noop는 비밀번호에 대한 암호화 처리를 하지 않겠다는
	 * 의미 .roles("MANAGER");//권한을 설정할 때 사용
	 * 
	 * auth.inMemoryAuthentication() .withUser("admin") .password("{noop}admin123")
	 * .roles("ADMIN"); }
	 */
	
	
}
