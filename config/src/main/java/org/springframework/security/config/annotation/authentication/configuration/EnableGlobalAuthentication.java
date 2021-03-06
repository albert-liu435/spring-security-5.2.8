/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.config.annotation.authentication.configuration;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;

/**
 * 这个类主要引入了 AuthenticationConfiguration 目的主要为了构造 认证管理器 AuthenticationManager 。AuthenticationManager 十分重要后面我们会进行专门的分析。
 * The {@link EnableGlobalAuthentication} annotation signals that the annotated class can
 * be used to configure a global instance of {@link AuthenticationManagerBuilder}. For
 * example:
 *
 * <pre class="code">
 * &#064;Configuration
 * &#064;EnableGlobalAuthentication
 * public class MyGlobalAuthenticationConfiguration {
 *
 * 	&#064;Autowired
 * 	public void configureGlobal(AuthenticationManagerBuilder auth) {
 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;)
 * 				.and().withUser(&quot;admin&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;, &quot;ADMIN&quot;);
 *    }
 * }
 * </pre>
 * <p>
 * Annotations that are annotated with {@link EnableGlobalAuthentication} also signal that
 * the annotated class can be used to configure a global instance of
 * {@link AuthenticationManagerBuilder}. For example:
 *
 * <pre class="code">
 * &#064;Configuration
 * &#064;EnableWebSecurity
 * public class MyWebSecurityConfiguration extends WebSecurityConfigurerAdapter {
 *
 * 	&#064;Autowired
 * 	public void configureGlobal(AuthenticationManagerBuilder auth) {
 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;)
 * 				.and().withUser(&quot;admin&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;, &quot;ADMIN&quot;);
 *    }
 *
 * 	// Possibly overridden methods ...
 * }
 * </pre>
 * <p>
 * The following annotations are annotated with {@link EnableGlobalAuthentication}
 *
 * <ul>
 * <li>{@link EnableWebSecurity}</li>
 * <li>{@link EnableWebMvcSecurity}</li>
 * <li>{@link EnableGlobalMethodSecurity}</li>
 * </ul>
 * <p>
 * Configuring {@link AuthenticationManagerBuilder} in a class without the
 * {@link EnableGlobalAuthentication} annotation has unpredictable results.
 *
 * @author Rob Winch
 * @see EnableWebMvcSecurity
 * @see EnableWebSecurity
 * @see EnableGlobalMethodSecurity
 */
@Retention(value = java.lang.annotation.RetentionPolicy.RUNTIME)
@Target(value = {java.lang.annotation.ElementType.TYPE})
@Documented
//它实际上激活了 AuthenticationConfiguration 这样的一个配置类，用来配置认证相关的核心类。
@Import(AuthenticationConfiguration.class)
@Configuration
public @interface EnableGlobalAuthentication {
}
