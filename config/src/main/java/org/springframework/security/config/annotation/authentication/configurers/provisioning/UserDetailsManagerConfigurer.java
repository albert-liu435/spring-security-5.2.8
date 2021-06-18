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
import java.util.List;

import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.UserDetailsServiceConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.UserDetailsManager;

/**
 * https://andyboke.blog.csdn.net/article/details/90742438
 * UserDetailsManagerConfigurer是Spring Security Config提供的一个安全配置器基类，用于配置安全构建器ProviderManagerBuilder,它继承自UserDetailsServiceConfigurer。UserDetailsManagerConfigurer对来自基类的能力作了如下定义 :
 * <p>
 * 改造定义 : 约定所使用的UserDetailsService 其实是UserDetailsService的子接口UserDetailsManager;
 * 扩展定义 : 提供了增加要被管理的用户账号详情的能力#withUser;
 * 用户账号详情可以通过UserDetailsBuilder,User.UserBuilder,UserDetails等形式被添加进来;
 * <p>
 * 扩展定义 : 实现基类定义的#initUserDetailsService 初始化UserDetailsService,其实是将上面添加进来的用户账号详情添加到UserDetailsService中去；
 * Base class for populating an
 * {@link org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder}
 * with a {@link UserDetailsManager}.
 *
 * @param <B> the type of the {@link SecurityBuilder} that is being configured
 * @param <C> the type of {@link UserDetailsManagerConfigurer}
 * @author Rob Winch
 * @since 3.2
 */
public class UserDetailsManagerConfigurer<B extends ProviderManagerBuilder<B>, C extends UserDetailsManagerConfigurer<B, C>>
		extends UserDetailsServiceConfigurer<B, C, UserDetailsManager> {
	// 用于初始化 UserDetailsManager 的 UserDetailsBuilder
	private final List<UserDetailsBuilder> userBuilders = new ArrayList<>();

	// 用于初始化 UserDetailsManager 的 UserDetails
	private final List<UserDetails> users = new ArrayList<>();

	/**
	 * 构造函数接收一个UserDetailsManager，这个UserDetailsManager是UserDetailsService的扩展，提供创建新用户和更新现有用户的能力。
	 * 在initUserDetailsService()方法中会使用withUser()方法接收的UserDetails或UserBuilder通过UserDetailsManager来初始创建一些用户。
	 *
	 * @param userDetailsManager
	 */
	protected UserDetailsManagerConfigurer(UserDetailsManager userDetailsManager) {
		super(userDetailsManager);
	}

	/**
	 * 填充已经添加的用户
	 * 初始化 UserDetailsService， 使用外部指定的用户账号详情: users,userBuilders
	 * Populates the users that have been added.
	 *
	 * @throws Exception
	 */
	@Override
	protected void initUserDetailsService() throws Exception {
		for (UserDetailsBuilder userBuilder : userBuilders) {
			getUserDetailsService().createUser(userBuilder.build());
		}
		for (UserDetails userDetails : this.users) {
			getUserDetailsService().createUser(userDetails);
		}
	}

	/**
	 * //允许将用户添加到正在创建的UserDetailsManager。 可以多次调用此方法以添加多个用户。
	 * Allows adding a user to the {@link UserDetailsManager} that is being created. This
	 * method can be invoked multiple times to add multiple users.
	 *
	 * @param userDetails the user to add. Cannot be null.
	 * @return the {@link UserDetailsBuilder} for further customizations
	 */
	@SuppressWarnings("unchecked")
	public final C withUser(UserDetails userDetails) {
		this.users.add(userDetails);
		return (C) this;
	}

	/**
	 * //允许将用户添加到正在创建的UserDetailsManager。 可以多次调用此方法以添加多个用户。
	 * Allows adding a user to the {@link UserDetailsManager} that is being created. This
	 * method can be invoked multiple times to add multiple users.
	 *
	 * @param userBuilder the user to add. Cannot be null.
	 * @return the {@link UserDetailsBuilder} for further customizations
	 */
	@SuppressWarnings("unchecked")
	public final C withUser(User.UserBuilder userBuilder) {
		this.users.add(userBuilder.build());
		return (C) this;
	}

	/**
	 * 允许添加user到UserDetailsManager
	 * Allows adding a user to the {@link UserDetailsManager} that is being created. This
	 * method can be invoked multiple times to add multiple users.
	 *
	 * @param username the username for the user being added. Cannot be null.
	 * @return the {@link UserDetailsBuilder} for further customizations
	 */
	@SuppressWarnings("unchecked")
	public final UserDetailsBuilder withUser(String username) {
		//创建UserDetailsBuilder
		UserDetailsBuilder userBuilder = new UserDetailsBuilder((C) this);
		//设置用户名
		userBuilder.username(username);
		//添加到集合中
		this.userBuilders.add(userBuilder);
		return userBuilder;
	}

	/**
	 * 构建添加用户，至少需要用户名，密码，和authorities
	 * Builds the user to be added. At minimum the username, password, and authorities
	 * should provided. The remaining attributes have reasonable defaults.
	 */
	public class UserDetailsBuilder {
		//拥有构建用户账户
		private UserBuilder user;
		private final C builder;

		/**
		 * Creates a new instance
		 *
		 * @param builder the builder to return
		 */
		private UserDetailsBuilder(C builder) {
			this.builder = builder;
		}

		/**
		 * Returns the {@link UserDetailsManagerConfigurer} for method chaining (i.e. to add
		 * another user)
		 *
		 * @return the {@link UserDetailsManagerConfigurer} for method chaining
		 */
		public C and() {
			return builder;
		}

		/**
		 * 设置用户名
		 * Populates the username. This attribute is required.
		 *
		 * @param username the username. Cannot be null.
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 */
		private UserDetailsBuilder username(String username) {
			this.user = User.withUsername(username);
			return this;
		}

		/**
		 * 填充密码
		 * Populates the password. This attribute is required.
		 *
		 * @param password the password. Cannot be null.
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 */
		public UserDetailsBuilder password(String password) {
			this.user.password(password);
			return this;
		}

		/**
		 * 填充roles的快捷方法
		 * Populates the roles. This method is a shortcut for calling
		 * {@link #authorities(String...)}, but automatically prefixes each entry with
		 * "ROLE_". This means the following:
		 *
		 * <code>
		 * builder.roles("USER","ADMIN");
		 * </code>
		 * <p>
		 * is equivalent to
		 *
		 * <code>
		 * builder.authorities("ROLE_USER","ROLE_ADMIN");
		 * </code>
		 *
		 * <p>
		 * This attribute is required, but can also be populated with
		 * {@link #authorities(String...)}.
		 * </p>
		 *
		 * @param roles the roles for this user (i.e. USER, ADMIN, etc). Cannot be null,
		 *              contain null values or start with "ROLE_"
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 */
		public UserDetailsBuilder roles(String... roles) {
			this.user.roles(roles);
			return this;
		}

		/**
		 * Populates the authorities. This attribute is required.
		 *
		 * @param authorities the authorities for this user. Cannot be null, or contain
		 *                    null values
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 * @see #roles(String...)
		 */
		public UserDetailsBuilder authorities(GrantedAuthority... authorities) {
			this.user.authorities(authorities);
			return this;
		}

		/**
		 * Populates the authorities. This attribute is required.
		 *
		 * @param authorities the authorities for this user. Cannot be null, or contain
		 *                    null values
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 * @see #roles(String...)
		 */
		public UserDetailsBuilder authorities(List<? extends GrantedAuthority> authorities) {
			this.user.authorities(authorities);
			return this;
		}

		/**
		 * Populates the authorities. This attribute is required.
		 *
		 * @param authorities the authorities for this user (i.e. ROLE_USER, ROLE_ADMIN,
		 *                    etc). Cannot be null, or contain null values
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 * @see #roles(String...)
		 */
		public UserDetailsBuilder authorities(String... authorities) {
			this.user.authorities(authorities);
			return this;
		}

		/**
		 * Defines if the account is expired or not. Default is false.
		 *
		 * @param accountExpired true if the account is expired, false otherwise
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 */
		public UserDetailsBuilder accountExpired(boolean accountExpired) {
			this.user.accountExpired(accountExpired);
			return this;
		}

		/**
		 * Defines if the account is locked or not. Default is false.
		 *
		 * @param accountLocked true if the account is locked, false otherwise
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 */
		public UserDetailsBuilder accountLocked(boolean accountLocked) {
			this.user.accountLocked(accountLocked);
			return this;
		}

		/**
		 * Defines if the credentials are expired or not. Default is false.
		 *
		 * @param credentialsExpired true if the credentials are expired, false otherwise
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 */
		public UserDetailsBuilder credentialsExpired(boolean credentialsExpired) {
			this.user.credentialsExpired(credentialsExpired);
			return this;
		}

		/**
		 * Defines if the account is disabled or not. Default is false.
		 *
		 * @param disabled true if the account is disabled, false otherwise
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 */
		public UserDetailsBuilder disabled(boolean disabled) {
			this.user.disabled(disabled);
			return this;
		}

		UserDetails build() {
			return this.user.build();
		}
	}
}
