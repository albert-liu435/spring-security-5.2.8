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
package org.springframework.security.config.annotation.authentication.configurers.userdetails;

import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * https://andyboke.blog.csdn.net/article/details/90741251
 * <p>
 * UserDetailsServiceConfigurer是Spring Security Config提供的一个安全配置器基类，用于配置安全构建器ProviderManagerBuilder,它继承自AbstractDaoAuthenticationConfigurer。UserDetailsServiceConfigurer对来自基类的能力作了如下定义 :
 * <p>
 * 扩展定义 : 提供一个初始化UserDetailsService的空方法#initUserDetailsService，子类可以根据情况予以实现;
 * 在该初始化过程中，可能会执行一些准备工作，比如用户账号详情存储结构的创建，或者创建一些用户账号；
 * <p>
 * 改造定义 : 重写基类配置方法，首先调用#initUserDetailsService初始化UserDetailsService ,然后调用基类配置方法#configure配置目标安全构建器;
 * 用于配置UserDetailsService
 * Allows configuring a {@link UserDetailsService} within a
 * {@link AuthenticationManagerBuilder}.
 *
 * @param <B> the type of the {@link ProviderManagerBuilder}
 * @param <C> the {@link UserDetailsServiceConfigurer} (or this)
 * @param <U> the type of UserDetailsService being used to allow for returning the
 *            concrete UserDetailsService.
 * @author Rob Winch
 * @since 3.2
 */
public class UserDetailsServiceConfigurer<B extends ProviderManagerBuilder<B>, C extends UserDetailsServiceConfigurer<B, C, U>, U extends UserDetailsService>
		extends AbstractDaoAuthenticationConfigurer<B, C, U> {

	/**
	 * Creates a new instance
	 *
	 * @param userDetailsService the {@link UserDetailsService} that should be used
	 */
	public UserDetailsServiceConfigurer(U userDetailsService) {
		super(userDetailsService);
	}

	@Override
	public void configure(B builder) throws Exception {
		// 初始化所使用的 UserDetailsService
		initUserDetailsService();
// 调用基类定义的配置方法配置目标安全构建器 builder,
		// 其实是向 builder 设置一个 DaoAuthenticationProvider 实例
		super.configure(builder);
	}

	/**
	 * 允许子类实例化UserDetailsService，比如添加users
	 * 定义一个 UserDetailsService 初始化方法，允许实现子类提供所使用的 UserDetailsService
	 * 的初始化逻辑，这些初始化逻辑会在当前安全配置器配置目标安全构建器前使用
	 * Allows subclasses to initialize the {@link UserDetailsService}. For example, it
	 * might add users, initialize schema, etc.
	 */
	protected void initUserDetailsService() throws Exception {
	}
}
