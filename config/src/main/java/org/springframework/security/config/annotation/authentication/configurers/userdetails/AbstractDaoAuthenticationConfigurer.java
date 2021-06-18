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

import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;

/**
 * AbstractDaoAuthenticationConfigurer是Spring Security Config提供的一个安全配置器抽象基类，它继承自UserDetailsAwareConfigurer,而UserDetailsAwareConfigurer又继承自SecurityConfigurerAdapter,实现了接口SecurityConfigurer。除了来自基类和所实现接口定义的能力，AbstractDaoAuthenticationConfigurer自身又为一个安全配置器进行了如下定义:
 * <p>
 * 所要创建的AuthenticationProvider是一个DaoAuthenticationProvider;
 * 提供使用者设定目标DaoAuthenticationProvider属性userDetailsService/userDetailsPasswordService的功能;
 * 提供使用者设定目标DaoAuthenticationProvider属性passwordEncoder的功能;
 * 提供使用者设定配置过程中安全对象后置处理器的功能;
 * 作为一个SecurityConfigurer，AbstractDaoAuthenticationConfigurer的安全构建器初始化方法为空,而配置方法流程是:
 * <p>
 * 对目标AuthenticationProvider DaoAuthenticationProvider执行后置处理;
 * 将目标AuthenticationProvider DaoAuthenticationProvider设置到目标安全构建器;
 * 用于配置DaoAuthenticationProvider
 * Allows configuring a {@link DaoAuthenticationProvider}
 *
 * @param <B> the type of the {@link SecurityBuilder}
 * @param <C> the type of {@link AbstractDaoAuthenticationConfigurer} this is
 * @param <U> The type of {@link UserDetailsService} that is being used
 * @author Rob Winch
 * @since 3.2
 */
abstract class AbstractDaoAuthenticationConfigurer<B extends ProviderManagerBuilder<B>, C extends AbstractDaoAuthenticationConfigurer<B, C, U>, U extends UserDetailsService>
		extends UserDetailsAwareConfigurer<B, U> {

	//获取DaoAuthenticationProvider,这个是默认的配置
	// 将要配置到目标安全构建器的 AuthenticationProvider， 是一个 DaoAuthenticationProvider
	private DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
	// 将要设置到 provider 的 UserDetailsService ，可以是 UserDetailsService 的子类，将会由
	// 使用者提供
	private final U userDetailsService;

	/**
	 * //需要一个UserDetailsService
	 * 构造函数，使用指定的 UserDetailsService 或者 UserDetailsPasswordService
	 * Creates a new instance
	 *
	 * @param userDetailsService
	 */
	protected AbstractDaoAuthenticationConfigurer(U userDetailsService) {
		// 记录使用者提供的 UserDetailsService
		this.userDetailsService = userDetailsService;
//  设置 userDetailsService 到 provider
		provider.setUserDetailsService(userDetailsService);
		//
		if (userDetailsService instanceof UserDetailsPasswordService) {
			//
			this.provider.setUserDetailsPasswordService((UserDetailsPasswordService) userDetailsService);
		}
	}

	/**
	 * //为此类添加ObjectPostProcessor
	 * 增加一个provider对象的后置处理器
	 * Adds an {@link ObjectPostProcessor} for this class.
	 *
	 * @param objectPostProcessor
	 * @return the {@link AbstractDaoAuthenticationConfigurer} for further customizations
	 */
	@SuppressWarnings("unchecked")
	public C withObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
		addObjectPostProcessor(objectPostProcessor);
		return (C) this;
	}

	/**
	 * //允许指定PasswordEncoder与DaoAuthenticationProvider一起使用。 默认是使用纯文本。
	 * 设置所要配置到安全构建器上的provider的密码加密器
	 * Allows specifying the {@link PasswordEncoder} to use with the
	 * {@link DaoAuthenticationProvider}. The default is to use plain text.
	 *
	 * @param passwordEncoder The {@link PasswordEncoder} to use.
	 * @return the {@link AbstractDaoAuthenticationConfigurer} for further customizations
	 */
	@SuppressWarnings("unchecked")
	public C passwordEncoder(PasswordEncoder passwordEncoder) {
		provider.setPasswordEncoder(passwordEncoder);
		return (C) this;
	}
	// 供使用者设置 provider 属性 userDetailsPasswordService 的工具方法
	public C userDetailsPasswordManager(UserDetailsPasswordService passwordManager) {
		provider.setUserDetailsPasswordService(passwordManager);
		return (C) this;
	}

	/**
	 * 在configure()方法中主要为ProviderManagerBuilder实例(在这里也就是指AuthenticationManagerBuilder)配置了一个DaoAuthenticationProvider，
	 * 这个DaoAuthenticationProvider实现了InitializingBean接口，要求其成员变量userDetailsService不可为null，userDetailsService在AbstractDaoAuthenticationConfigurer构造方法中配置。
	 *
	 * @param builder
	 * @throws Exception
	 */
	@Override
	public void configure(B builder) throws Exception {
		//使用祖先类SecurityConfigurerAdapter通过addObjectPostProcessor()方法添加的ObjectPostProcessor初始化对象
		//可能返回应该使用的修改实例。
		provider = postProcess(provider);
		//将DaoAuthenticationProvider加入到AuthenticationManagerBuilder的authenticationProviders中
		builder.authenticationProvider(provider);
	}

	/**
	 * 获取userDetailsService
	 * Gets the {@link UserDetailsService} that is used with the
	 * {@link DaoAuthenticationProvider}
	 *
	 * @return the {@link UserDetailsService} that is used with the
	 * {@link DaoAuthenticationProvider}
	 */
	public U getUserDetailsService() {
		return userDetailsService;
	}
}
