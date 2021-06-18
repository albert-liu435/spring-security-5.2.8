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
package org.springframework.security.config.annotation.authentication.configurers.provisioning;

import java.util.ArrayList;

import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * https://andyboke.blog.csdn.net/article/details/90738990
 * InMemoryUserDetailsManagerConfigurer是Spring Security Config提供的一个安全配置器SecurityConfigurer,用来配置一个安全构建器ProviderManagerBuilder(通常可以认为就是AuthenticationManagerBuilder),它为目标安全构建器提供的是一个基于内存存储用户账号详情的用户账号详情管理对象DaoAuthenticationProvider。
 * <p>
 * 具体来讲，InMemoryUserDetailsManagerConfigurer实现了接口SecurityConfigurer，它的主要配置动作是:
 * <p>
 * 创建一个InMemoryUserDetailsManager(UserDetailsManager/UserDetailsService的一个实现类);
 * 创建一个DaoAuthenticationProvider,将上面所创建的InMemoryUserDetailsManager作为自己的UserDetailsService userDetailsService属性;
 * 将上面所创建的DaoAuthenticationProvider添加到目标构建器ProviderManagerBuilder上。
 * 另外，因为InMemoryUserDetailsManagerConfigurer继承自UserDetailsManagerConfigurer,所以UserDetailsManagerConfigurer所具备的能力,InMemoryUserDetailsManagerConfigurer都拥有。
 * <p>
 * 注意 : InMemoryUserDetailsManagerConfigurer和所提供的InMemoryUserDetailsManager主要应用于开发调试环境，其设计目的主要是测试和功能演示，一般不在生产环境中使用。
 * 配置AuthenticationManagerBuilder到内存认证，并且很容易添加用户
 * 使用InMemoryUserDetailsManager完成用户在内存中的创建、更新等操作。
 * Configures an
 * {@link org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder}
 * to have in memory authentication. It also allows easily adding users to the in memory
 * authentication.
 *
 * @param <B> the type of the {@link ProviderManagerBuilder} that is being configured
 * @author Rob Winch
 * @since 3.2
 */
public class InMemoryUserDetailsManagerConfigurer<B extends ProviderManagerBuilder<B>>
		extends UserDetailsManagerConfigurer<B, InMemoryUserDetailsManagerConfigurer<B>> {

	/**
	 * 创建一个实例
	 * Creates a new instance
	 */
	public InMemoryUserDetailsManagerConfigurer() {
		super(new InMemoryUserDetailsManager(new ArrayList<>()));
	}
}
