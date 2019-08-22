package com.rubypaper.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity //�� Ŭ�����κ��� ������ ��ü�� ��ť��Ƽ ���� �������� �ǹ�, ���ÿ� ��ť��Ƽ�� ����ϴµ� �ʿ��� ������ ��ü�� �����Ѵ�.
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Autowired
	private BoardUserDetailsService boardUserDetailsService;
	
	
	/*
	 * @Autowired private DataSource dataSource;
	 */
	
	@Override
	protected void configure(HttpSecurity security) throws Exception{
		security.authorizeRequests().antMatchers("/").permitAll(); //��� ����ڿ��� ���� ���
		security.authorizeRequests().antMatchers("/member/**").authenticated(); //������ ����ڸ� �������
		security.authorizeRequests().antMatchers("/manager/**").hasRole("MANAGER"); //hasRole("����")�� Ư�� ������ ���� ����ڸ� ���� ���
		security.authorizeRequests().antMatchers("/admin/**").hasRole("ADMIN");
		
		security.csrf().disable();
		security.formLogin().loginPage("/login").defaultSuccessUrl("/loginSuccess", true); //����ڿ��� �α��� ȭ���� ����
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
	 * @Autowired//�Ű����� ������ ���� public void authenticate(AuthenticationManagerBuilder
	 * auth) throws Exception{//�޸𸮿� ����� ������ �����ϰ� �����ҷ��� ����
	 * auth.inMemoryAuthentication() //�޸𸮿� ����� ������ �����ϴ� �޼ҵ� .withUser("manager")
	 * //������ ������� ���̵� .password("{noop}manager123") //noop�� ��й�ȣ�� ���� ��ȣȭ ó���� ���� �ʰڴٴ�
	 * �ǹ� .roles("MANAGER");//������ ������ �� ���
	 * 
	 * auth.inMemoryAuthentication() .withUser("admin") .password("{noop}admin123")
	 * .roles("ADMIN"); }
	 */
	
	
}
