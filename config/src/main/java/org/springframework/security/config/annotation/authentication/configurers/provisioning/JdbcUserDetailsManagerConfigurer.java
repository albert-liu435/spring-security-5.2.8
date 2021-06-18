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

import javax.sql.DataSource;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.datasource.init.DataSourceInitializer;
import org.springframework.jdbc.datasource.init.DatabasePopulator;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

/**
 * JdbcUserDetailsManagerConfigurer是Spring Security Config提供的一个安全配置器SecurityConfigurer,用来配置一个安全构建器ProviderManagerBuilder(通常可以认为就是AuthenticationManagerBuilder),它为目标安全构建器提供的是一个基于关系型数据库的用户账号详情管理对象DaoAuthenticationProvider。
 * <p>
 * 具体来讲，JdbcUserDetailsManagerConfigurer实现了接口SecurityConfigurer，它的主要配置动作是:
 * <p>
 * 创建一个JdbcUserDetailsManager(UserDetailsManager/UserDetailsService的一个实现类);
 * 创建一个DaoAuthenticationProvider,将上面所创建的JdbcUserDetailsManager作为自己的UserDetailsService userDetailsService属性;
 * 将上面所创建的DaoAuthenticationProvider添加到目标构建器ProviderManagerBuilder上。
 * 除了以上主要的配置能力，JdbcUserDetailsManagerConfigurer提供了其他一些辅助能力:
 * 1. 指定所要使用的数据源;
 * 2. 是否使用缺省脚本对数据源进行初始化;
 * 3. 如果是用的不是缺省表结构，允许指定相应的查询语句;
 * 4. 指定所要使用的权限前缀，缺省值为"";
 * <p>
 * 另外，因为JdbcUserDetailsManagerConfigurer继承自UserDetailsManagerConfigurer,所以UserDetailsManagerConfigurer所具备的能力,JdbcUserDetailsManagerConfigurer都拥有。
 * <p>
 * <p>
 * 配置AuthenticationManagerBuilder以进行JDBC身份验证。 它还允许轻松地将用户添加到用于身份验证和设置架构的数据库中。唯一需要的方法是dataSource(DataSource)，其他所有方法都有合理的默认值。
 * Configures an
 * {@link org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder}
 * to have JDBC authentication. It also allows easily adding users to the database used
 * for authentication and setting up the schema.
 *
 * <p>
 * The only required method is the {@link #dataSource(javax.sql.DataSource)} all other
 * methods have reasonable defaults.
 *
 * @param <B> the type of the {@link ProviderManagerBuilder} that is being configured
 * @author Rob Winch
 * @since 3.2
 */
public class JdbcUserDetailsManagerConfigurer<B extends ProviderManagerBuilder<B>>
		extends UserDetailsManagerConfigurer<B, JdbcUserDetailsManagerConfigurer<B>> {
	// 创建目标 JdbcUserDetailsManager 所要使用的数据源
	private DataSource dataSource;
	// 如果要在数据源中初始化所需表格，这里是初始化脚本
	private List<Resource> initScripts = new ArrayList<>();

	// 构造函数，使用外部指定的 JdbcUserDetailsManager 对象
	public JdbcUserDetailsManagerConfigurer(JdbcUserDetailsManager manager) {
		super(manager);
	}

	// 构造函数，使用内部新建的 JdbcUserDetailsManager 对象
	public JdbcUserDetailsManagerConfigurer() {
		this(new JdbcUserDetailsManager());
	}

	/**
	 * 使用外部指定的数据源,改参数不能是 null
	 * 该数据源会被用于当前对象 userDetailsService 属性
	 * (也就是上面构造函数里面提到的JdbcUserDetailsManager实例)的数据源
	 * Populates the {@link DataSource} to be used. This is the only required attribute.
	 *
	 * @param dataSource the {@link DataSource} to be used. Cannot be null.
	 * @return The {@link JdbcUserDetailsManagerConfigurer} used for additional customizations
	 */
	public JdbcUserDetailsManagerConfigurer<B> dataSource(DataSource dataSource) {
		this.dataSource = dataSource;
		getUserDetailsService().setDataSource(dataSource);
		return this;
	}

	/**
	 * //设置用于按用户名查找用户的查询。select username,password,enabled from users where username = ?
	 * 设置根据用户名查询用户账号信息的SQL语句。用在不使用缺省表格结构的情况。
	 * Sets the query to be used for finding a user by their username. For example:
	 *
	 * <code>
	 * select username,password,enabled from users where username = ?
	 * </code>
	 *
	 * @param query The query to use for selecting the username, password, and if the user
	 *              is enabled by username. Must contain a single parameter for the username.
	 * @return The {@link JdbcUserDetailsManagerConfigurer} used for additional
	 * customizations
	 */
	public JdbcUserDetailsManagerConfigurer<B> usersByUsernameQuery(String query) {
		getUserDetailsService().setUsersByUsernameQuery(query);
		return this;
	}

	/**
	 * //设置用于通过用户名查找用户权限的查询。 例如：select username,authority from authorities where username = ?
	 * 设置根据用户名查询用户权限的SQL语句。用在不使用缺省表格结构的情况。
	 * Sets the query to be used for finding a user's authorities by their username. For
	 * example:
	 *
	 * <code>
	 * select username,authority from authorities where username = ?
	 * </code>
	 *
	 * @param query The query to use for selecting the username, authority by username.
	 *              Must contain a single parameter for the username.
	 * @return The {@link JdbcUserDetailsManagerConfigurer} used for additional
	 * customizations
	 */
	public JdbcUserDetailsManagerConfigurer<B> authoritiesByUsernameQuery(String query) {
		getUserDetailsService().setAuthoritiesByUsernameQuery(query);
		return this;
	}

	/**
	 * //给定用户名的SQL语句，用于查询用户的组权限。 例如：
	 * //select g.id, g.group_name, ga.authority from groups g, group_members gm, group_authorities ga
	 * //where gm.username = ? and g.id = ga.group_id and g.id = gm.group_id
	 * <p>
	 * 设置查询用户所属组的权限的SQL语句。用在不使用缺省表格结构并启用了用户组功能的情况。
	 * An SQL statement to query user's group authorities given a username. For example:
	 *
	 * <code>
	 * select
	 * g.id, g.group_name, ga.authority
	 * from
	 * groups g, group_members gm, group_authorities ga
	 * where
	 * gm.username = ? and g.id = ga.group_id and g.id = gm.group_id
	 * </code>
	 *
	 * @param query The query to use for selecting the authorities by group. Must contain
	 *              a single parameter for the username.
	 * @return The {@link JdbcUserDetailsManagerConfigurer} used for additional
	 * customizations
	 */
	public JdbcUserDetailsManagerConfigurer<B> groupAuthoritiesByUsername(String query) {
		JdbcUserDetailsManager userDetailsService = getUserDetailsService();
		userDetailsService.setEnableGroups(true);
		userDetailsService.setGroupAuthoritiesByUsernameQuery(query);
		return this;
	}

	/**
	 * //一个非空字符串前缀，将添加到从持久存储加载的角色字符串中（默认为“”）。
	 * A non-empty string prefix that will be added to role strings loaded from persistent
	 * storage (default is "").
	 *
	 * @param rolePrefix
	 * @return The {@link JdbcUserDetailsManagerConfigurer} used for additional customizations
	 */
	public JdbcUserDetailsManagerConfigurer<B> rolePrefix(String rolePrefix) {
		getUserDetailsService().setRolePrefix(rolePrefix);
		return this;
	}

	/**
	 * //设置缓存实现
	 * Defines the {@link UserCache} to use
	 *
	 * @param userCache the {@link UserCache} to use
	 * @return the {@link JdbcUserDetailsManagerConfigurer} for further customizations
	 */
	public JdbcUserDetailsManagerConfigurer<B> userCache(UserCache userCache) {
		getUserDetailsService().setUserCache(userCache);
		return this;
	}


	// 初始化 userDetailsService JdbcUserDetailsManager ：
	// 1. 如果初始化脚本存在，则使用初始化脚本初始化数据源(创建相应表格结构);
	// 2. 如果外部指定了用户账号信息，将这些用户账号信息添加到 userDetailsService
	//   JdbcUserDetailsManager，从而使它们处于管理之中。
	@Override
	protected void initUserDetailsService() throws Exception {
		//加载数据库初始脚本
		if (!initScripts.isEmpty()) {
			getDataSourceInit().afterPropertiesSet();
		}
		super.initUserDetailsService();
	}

	@Override
	public JdbcUserDetailsManager getUserDetailsService() {
		return (JdbcUserDetailsManager) super.getUserDetailsService();
	}

	/**
	 * //填充允许存储用户和权限的默认架构。
	 * 获取缺省的数据源初始化脚本，注意该内置脚本仅仅针对 H2 数据库，对于 MySQL, Oracle
	 * 此脚本并不适用
	 * Populates the default schema that allows users and authorities to be stored.
	 *
	 * @return The {@link JdbcUserDetailsManagerConfigurer} used for additional
	 * customizations
	 */
	public JdbcUserDetailsManagerConfigurer<B> withDefaultSchema() {
		this.initScripts.add(new ClassPathResource(
				"org/springframework/security/core/userdetails/jdbc/users.ddl"));
		return this;
	}

	// 创建数据库填充器对象
	protected DatabasePopulator getDatabasePopulator() {
		ResourceDatabasePopulator dbp = new ResourceDatabasePopulator();
		dbp.setScripts(initScripts.toArray(new Resource[0]));
		return dbp;
	}

	// 获取数据源初始化器对象，该对象基于上面提到的数据库填充器对象和所设置的数据源
	private DataSourceInitializer getDataSourceInit() {
		DataSourceInitializer dsi = new DataSourceInitializer();
		dsi.setDatabasePopulator(getDatabasePopulator());
		dsi.setDataSource(dataSource);
		return dsi;
	}
}
