/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.configuration;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;

/**
 * https://blog.csdn.net/fengyilin_henu/article/details/84915627
 *
 *注释中提到两个很重要的点，以及一个配置示例，
 *
 * 第一个点：@EnableWebSecurity配置到拥有注解 @Configuration的类上，就可以获取到spring security的支持.
 * 第二个点: WebSecurityConfigurer的子类可以扩展spring security的应用
 * 由此可知@EnableWebSecurity使我们拥有spring security的能力。WebSecurityConfigurer 使我们能根据业务扩展我们的应用,而WebSecurityConfigurerAdapter是WebSecurityConfigurer 的一个适配器，
 * 必然也是做了很多默认的工作。后面我们会一一说到。
 *
 * 作者：怪诞140819
 * 链接：https://www.jianshu.com/p/0c54788c94f3
 * 来源：简书
 * 著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。
 * Add this annotation to an {@code @Configuration} class to have the Spring Security
 * configuration defined in any {@link WebSecurityConfigurer} or more likely by extending
 * the {@link WebSecurityConfigurerAdapter} base class and overriding individual methods:
 *
 * <pre class="code">
 * &#064;Configuration
 * &#064;EnableWebSecurity
 * public class MyWebSecurityConfiguration extends WebSecurityConfigurerAdapter {
 *
 * 	&#064;Override
 * 	public void configure(WebSecurity web) throws Exception {
 * 		web.ignoring()
 * 		// Spring Security should completely ignore URLs starting with /resources/
 * 				.antMatchers(&quot;/resources/**&quot;);
 *    }
 *
 * 	&#064;Override
 * 	protected void configure(HttpSecurity http) throws Exception {
 * 		http.authorizeRequests().antMatchers(&quot;/public/**&quot;).permitAll().anyRequest()
 * 				.hasRole(&quot;USER&quot;).and()
 * 				// Possibly more configuration ...
 * 				.formLogin() // enable form based log in
 * 				// set permitAll for all URLs associated with Form Login
 * 				.permitAll();
 *    }
 *
 * 	&#064;Override
 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
 * 		auth
 * 		// enable in memory based authentication with a user named &quot;user&quot; and &quot;admin&quot;
 * 		.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;)
 * 				.and().withUser(&quot;admin&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;, &quot;ADMIN&quot;);
 *    }
 *
 * 	// Possibly more overridden methods ...
 * }
 * </pre>
 *
 * @author Rob Winch
 * @see WebSecurityConfigurer
 * @see WebSecurityConfigurerAdapter
 * @since 3.2
 */
//@Enable* 这类注解都是带配置导入的注解。通过导入一些配置来启用一些特定功能。
@Retention(value = java.lang.annotation.RetentionPolicy.RUNTIME)
@Target(value = {java.lang.annotation.ElementType.TYPE})
@Documented
//SpringWebMvcImportSelector 的作用是判断当前的环境是否包含 springmvc，因为 spring security 可以在非 spring 环境下使用，为了避免 DispatcherServlet 的重复配置，所以使用了这个注解来区分。
//WebSecurityConfiguration 顾名思义，是用来配置 web 安全的
@Import({WebSecurityConfiguration.class,
		SpringWebMvcImportSelector.class,
		OAuth2ImportSelector.class})
@EnableGlobalAuthentication
@Configuration
public @interface EnableWebSecurity {

	/**
	 * 控制是否支持debug模式
	 * Controls debugging support for Spring Security. Default is false.
	 *
	 * @return if true, enables debug support with Spring Security
	 */
	boolean debug() default false;
}
