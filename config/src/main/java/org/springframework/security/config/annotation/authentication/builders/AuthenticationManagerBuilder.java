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
package org.springframework.security.config.annotation.authentication.builders;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.ldap.LdapAuthenticationProviderConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.JdbcUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.UserDetailsAwareConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.Assert;

/**
 * https://andyboke.blog.csdn.net/article/details/90665519
 * <p>
 * AuthenticationManagerBuilder典型的用法是 :
 * <p>
 * 根据需求设置相应属性;
 * 设置双亲AuthenticationManager(可选,缺省值无)：#parentAuthenticationManager();
 * 设置认证事件发布器(可选,缺省值无):#authenticationEventPublisher();
 * 设置是否认证后从认证对象中擦除密码信息(缺省为false,可选):#eraseCredentials();
 * 根据需要应用相应的认证安全配置器SecurityConfigurer(可以应用多个,也可以一个都不应用)
 * #jdbcAuthentication()，对应JdbcUserDetailsManagerConfigurer
 * #inMemoryAuthentication() , 对应InMemoryUserDetailsManagerConfigurer
 * #ldapAuthentication() , 对应LdapAuthenticationProviderConfigurer
 * 这里每个SecurityConfigurer 都用于生成一个AuthenticationProvider并添加到所配置的目标AuthenticationManagerBuilder上
 * <p>
 * 可以再提供一个自定义的UserDetailsService (也可以不提供)
 * 其实是将一个UserDetailsService包装成了一个SecurityConfigurer DaoAuthenticationConfigurer 然后应用到目标AuthenticationManagerBuilder上,最终也是生成一个AuthenticationProvider并添加到所配置的目标AuthenticationManagerBuilder上
 * <p>
 * 可以提供若干个自定义的AuthenticationProvider(也可以不提供)
 * 注意:以上2,3,4 步骤中提供的AuthenticationProvider必须至少有一个,或者必须为AuthenticationManagerBuilder设置双亲(parent)AuthenticationManager;
 * <p>
 * 调用#build 方法构建目标AuthenticationManager供使用方使用
 * <p>
 * <p>
 * <p>
 * https://blog.csdn.net/shenchaohao12321/article/details/87721655
 * 在使用AuthenticationManagerBuilder构建AuthenticationManager时，我们通常会遇到以下三种SecurityConfigurer ：
 * <p>
 * InMemoryUserDetailsManagerConfigurer
 * 基于内存存储用户账号详情的安全配置器,
 * 最终生成一个DaoAuthenticationProvider,内含一个UserDetailsService InMemoryUserDetailsManager
 * 通常用于开发调试环境，不用于生产环境
 * JdbcUserDetailsManagerConfigurer
 * 基于关系型数据库存储用户账号详情的安全配置器
 * 最终生成一个DaoAuthenticationProvider,内含一个UserDetailsService JdbcUserDetailsManager
 * LdapAuthenticationProviderConfigurer
 * 基于 LDAP存储用户账号详情的安全配置器
 * 最终生成一个LdapAuthenticationProvider
 * 这里需要注意的是 :
 * <p>
 * InMemoryUserDetailsManagerConfigurer和JdbcUserDetailsManagerConfigurer有更多的相似性，最终都是生成一个DaoAuthenticationProvider,内含一个UserDetailsService；二者所面向的用户账号详情存储形式类似，所以统一抽象成UserDetailsManagerConfigurer。
 * InMemoryUserDetailsManagerConfigurer/JdbcUserDetailsManagerConfigurer和LdapAuthenticationProviderConfigurer更不同,LdapAuthenticationProviderConfigurer所面向的用户账号存储形式是LDAP,所以单独抽象。
 * AuthenticationManagerBuilder用于创建AuthenticationManager。 允许轻松构建内存身份验证，LDAP身份验证，基于JDBC的身份验证，添加UserDetailsService以及添加AuthenticationProvider。
 * AuthenticationManagerBuilder除了可以使用上面提到的内存身份验证，LDAP身份验证，基于JDBC的身份验证，还可以使用userDetailsService()方法传入一个userDetailsService来实现自定义的身份验证。
 * {@link SecurityBuilder} used to create an {@link AuthenticationManager}. Allows for
 * easily building in memory authentication, LDAP authentication, JDBC based
 * authentication, adding {@link UserDetailsService}, and adding
 * {@link AuthenticationProvider}'s.
 *
 * @author Rob Winch
 * @since 3.2
 */
public class AuthenticationManagerBuilder
		extends
		AbstractConfiguredSecurityBuilder<AuthenticationManager, AuthenticationManagerBuilder>
		implements ProviderManagerBuilder<AuthenticationManagerBuilder> {
	private final Log logger = LogFactory.getLog(getClass());

	private AuthenticationManager parentAuthenticationManager;
	private List<AuthenticationProvider> authenticationProviders = new ArrayList<>();
	private UserDetailsService defaultUserDetailsService;
	//是否清除凭证。
	private Boolean eraseCredentials;
	private AuthenticationEventPublisher eventPublisher;

	/**
	 * Creates a new instance
	 *
	 * @param objectPostProcessor the {@link ObjectPostProcessor} instance to use.
	 */
	public AuthenticationManagerBuilder(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor, true);
	}

	/**
	 * Allows providing a parent {@link AuthenticationManager} that will be tried if this
	 * {@link AuthenticationManager} was unable to attempt to authenticate the provided
	 * {@link Authentication}.
	 *
	 * @param authenticationManager the {@link AuthenticationManager} that should be used
	 *                              if the current {@link AuthenticationManager} was unable to attempt to authenticate
	 *                              the provided {@link Authentication}.
	 * @return the {@link AuthenticationManagerBuilder} for further adding types of
	 * authentication
	 */
	public AuthenticationManagerBuilder parentAuthenticationManager(
			AuthenticationManager authenticationManager) {
		if (authenticationManager instanceof ProviderManager) {
			eraseCredentials(((ProviderManager) authenticationManager)
					.isEraseCredentialsAfterAuthentication());
		}
		this.parentAuthenticationManager = authenticationManager;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationEventPublisher}
	 *
	 * @param eventPublisher the {@link AuthenticationEventPublisher} to use
	 * @return the {@link AuthenticationManagerBuilder} for further customizations
	 */
	public AuthenticationManagerBuilder authenticationEventPublisher(
			AuthenticationEventPublisher eventPublisher) {
		Assert.notNull(eventPublisher, "AuthenticationEventPublisher cannot be null");
		this.eventPublisher = eventPublisher;
		return this;
	}

	/**
	 * @param eraseCredentials true if {@link AuthenticationManager} should clear the
	 *                         credentials from the {@link Authentication} object after authenticating
	 * @return the {@link AuthenticationManagerBuilder} for further customizations
	 */
	public AuthenticationManagerBuilder eraseCredentials(boolean eraseCredentials) {
		this.eraseCredentials = eraseCredentials;
		return this;
	}

	/**
	 * 添加基于内存身份认证到AuthenticationManagerBuilder实例中，并返回InMemoryUserDetailsManagerConfigurer允许自定义内存认证
	 * <p>
	 * //将内存身份验证添加到AuthenticationManagerBuilder并返回InMemoryUserDetailsManagerConfigurer以允许自定义内存中身份验证。
	 * //此方法还确保UserDetailsService可用于getDefaultUserDetailsService()方法。
	 * //请注意，其他UserDetailsService可能会覆盖此UserDetailsService作为默认值
	 * Add in memory authentication to the {@link AuthenticationManagerBuilder} and return
	 * a {@link InMemoryUserDetailsManagerConfigurer} to allow customization of the in
	 * memory authentication.
	 *
	 * <p>
	 * This method also ensure that a {@link UserDetailsService} is available for the
	 * {@link #getDefaultUserDetailsService()} method. Note that additional
	 * {@link UserDetailsService}'s may override this {@link UserDetailsService} as the
	 * default.
	 * </p>
	 *
	 * @return a {@link InMemoryUserDetailsManagerConfigurer} to allow customization of
	 * the in memory authentication
	 * @throws Exception if an error occurs when adding the in memory authentication
	 */
	public InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> inMemoryAuthentication()
			throws Exception {
		//
		return apply(new InMemoryUserDetailsManagerConfigurer<>());
	}

	/**
	 * //将JDBC身份验证添加到AuthenticationManagerBuilder并返回JdbcUserDetailsManagerConfigurer以允许自定义JDBC身份验证。
	 * //当使用持久性数据存储时，最好使用Flyway或Liquibase之类的东西添加配置外部的用户来创建模式并添加用户以确保这些步骤仅执行一次并且使用最佳SQL。
	 * //此方法还确保UserDetailsService可用于getDefaultUserDetailsService（）方法。
	 * //请注意，其他UserDetailsService可能会覆盖此UserDetailsService作为默认值。
	 * Add JDBC authentication to the {@link AuthenticationManagerBuilder} and return a
	 * {@link JdbcUserDetailsManagerConfigurer} to allow customization of the JDBC
	 * authentication.
	 *
	 * <p>
	 * When using with a persistent data store, it is best to add users external of
	 * configuration using something like <a href="https://flywaydb.org/">Flyway</a> or <a
	 * href="https://www.liquibase.org/">Liquibase</a> to create the schema and adding
	 * users to ensure these steps are only done once and that the optimal SQL is used.
	 * </p>
	 *
	 * <p>
	 * This method also ensure that a {@link UserDetailsService} is available for the
	 * {@link #getDefaultUserDetailsService()} method. Note that additional
	 * {@link UserDetailsService}'s may override this {@link UserDetailsService} as the
	 * default. See the <a href=
	 * "https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#user-schema"
	 * >User Schema</a> section of the reference for the default schema.
	 * </p>
	 *
	 * @return a {@link JdbcUserDetailsManagerConfigurer} to allow customization of the
	 * JDBC authentication
	 * @throws Exception if an error occurs when adding the JDBC authentication
	 */
	public JdbcUserDetailsManagerConfigurer<AuthenticationManagerBuilder> jdbcAuthentication()
			throws Exception {
		return apply(new JdbcUserDetailsManagerConfigurer<>());
	}

	/**
	 * //根据传入的自定义UserDetailsService添加身份验证。然后返回DaoAuthenticationConfigurer以允许自定义身份验证。
	 * //此方法还确保UserDetailsService可用于getDefaultUserDetailsService（）方法。 请注意，其他UserDetailsService可能会覆盖此UserDetailsService作为默认值
	 * Add authentication based upon the custom {@link UserDetailsService} that is passed
	 * in. It then returns a {@link DaoAuthenticationConfigurer} to allow customization of
	 * the authentication.
	 *
	 * <p>
	 * This method also ensure that the {@link UserDetailsService} is available for the
	 * {@link #getDefaultUserDetailsService()} method. Note that additional
	 * {@link UserDetailsService}'s may override this {@link UserDetailsService} as the
	 * default.
	 * </p>
	 *
	 * @return a {@link DaoAuthenticationConfigurer} to allow customization of the DAO
	 * authentication
	 * @throws Exception if an error occurs when adding the {@link UserDetailsService}
	 *                   based authentication
	 */
	public <T extends UserDetailsService> DaoAuthenticationConfigurer<AuthenticationManagerBuilder, T> userDetailsService(
			T userDetailsService) throws Exception {
		this.defaultUserDetailsService = userDetailsService;
		return apply(new DaoAuthenticationConfigurer<>(
				userDetailsService));
	}

	/**
	 * //将LDAP身份验证添加到AuthenticationManagerBuilder并返回LdapAuthenticationProviderConfigurer以允许自定义LDAP身份验证。
	 * //此方法不确保UserDetailsService可用于getDefaultUserDetailsService()方法
	 * Add LDAP authentication to the {@link AuthenticationManagerBuilder} and return a
	 * {@link LdapAuthenticationProviderConfigurer} to allow customization of the LDAP
	 * authentication.
	 *
	 * <p>
	 * This method <b>does NOT</b> ensure that a {@link UserDetailsService} is available
	 * for the {@link #getDefaultUserDetailsService()} method.
	 *
	 * @return a {@link LdapAuthenticationProviderConfigurer} to allow customization of
	 * the LDAP authentication
	 * @throws Exception if an error occurs when adding the LDAP authentication
	 */
	public LdapAuthenticationProviderConfigurer<AuthenticationManagerBuilder> ldapAuthentication()
			throws Exception {
		return apply(new LdapAuthenticationProviderConfigurer<>());
	}

	/**
	 * 添加AuthenticationProvider
	 * Add authentication based upon the custom {@link AuthenticationProvider} that is
	 * passed in. Since the {@link AuthenticationProvider} implementation is unknown, all
	 * customizations must be done externally and the {@link AuthenticationManagerBuilder}
	 * is returned immediately.
	 *
	 * <p>
	 * This method <b>does NOT</b> ensure that the {@link UserDetailsService} is available
	 * for the {@link #getDefaultUserDetailsService()} method.
	 * <p>
	 * Note that an {@link Exception} might be thrown if an error occurs when adding the {@link AuthenticationProvider}.
	 *
	 * @return a {@link AuthenticationManagerBuilder} to allow further authentication to
	 * be provided to the {@link AuthenticationManagerBuilder}
	 */
	public AuthenticationManagerBuilder authenticationProvider(
			AuthenticationProvider authenticationProvider) {
		this.authenticationProviders.add(authenticationProvider);
		return this;
	}

	/**
	 * 真正用于创建AuthenticationManager的performBuild()方法
	 *
	 * @return
	 * @throws Exception
	 */
	@Override
	protected ProviderManager performBuild() throws Exception {
		if (!isConfigured()) {
			logger.debug("No authenticationProviders and no parentAuthenticationManager defined. Returning null.");
			return null;
		}
		ProviderManager providerManager = new ProviderManager(authenticationProviders,
				parentAuthenticationManager);
		if (eraseCredentials != null) {
			providerManager.setEraseCredentialsAfterAuthentication(eraseCredentials);
		}
		if (eventPublisher != null) {
			providerManager.setAuthenticationEventPublisher(eventPublisher);
		}
		//使用Spring装配providerManager
		providerManager = postProcess(providerManager);
		return providerManager;
	}

	/**
	 * Determines if the {@link AuthenticationManagerBuilder} is configured to build a non
	 * null {@link AuthenticationManager}. This means that either a non-null parent is
	 * specified or at least one {@link AuthenticationProvider} has been specified.
	 *
	 * <p>
	 * When using {@link SecurityConfigurer} instances, the
	 * {@link AuthenticationManagerBuilder} will not be configured until the
	 * {@link SecurityConfigurer#configure(SecurityBuilder)} methods. This means a
	 * {@link SecurityConfigurer} that is last could check this method and provide a
	 * default configuration in the {@link SecurityConfigurer#configure(SecurityBuilder)}
	 * method.
	 *
	 * @return true, if {@link AuthenticationManagerBuilder} is configured, otherwise false
	 */
	public boolean isConfigured() {
		return !authenticationProviders.isEmpty() || parentAuthenticationManager != null;
	}

	/**
	 * Gets the default {@link UserDetailsService} for the
	 * {@link AuthenticationManagerBuilder}. The result may be null in some circumstances.
	 *
	 * @return the default {@link UserDetailsService} for the
	 * {@link AuthenticationManagerBuilder}
	 */
	public UserDetailsService getDefaultUserDetailsService() {
		return this.defaultUserDetailsService;
	}

	/**
	 * 获取UserDetailsService
	 * //依旧会调用AbstractConfiguredSecurityBuilder的apply()方法为AuthenticationManagerBuilder提供配置
	 * Captures the {@link UserDetailsService} from any {@link UserDetailsAwareConfigurer}
	 * .
	 *
	 * @param configurer the {@link UserDetailsAwareConfigurer} to capture the
	 *                   {@link UserDetailsService} from.
	 * @return the {@link UserDetailsAwareConfigurer} for further customizations
	 * @throws Exception if an error occurs
	 */
	private <C extends UserDetailsAwareConfigurer<AuthenticationManagerBuilder, ? extends UserDetailsService>> C apply(
			C configurer) throws Exception {
		//获取默认的UserDetailsService
		this.defaultUserDetailsService = configurer.getUserDetailsService();
		return super.apply(configurer);
	}
}
