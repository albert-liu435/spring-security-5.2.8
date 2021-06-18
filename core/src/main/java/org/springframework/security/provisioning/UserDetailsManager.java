/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.provisioning;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * https://andyboke.blog.csdn.net/article/details/90664433
 * UserDetailsManager是Spring Security的一个概念模型接口，用于抽象建模对用户详情的管理这一概念。它继承自接口UserDetailsService,是对UserDetailsService接口的能力扩展。
 * <p>
 * UserDetailsService定义了根据用户名获取用户详情的能力，UserDetailsManager在此基础上增加定义了如下能力 :
 * <p>
 * 创建用户账号 : void createUser(UserDetails user)
 * 更新用户账号 : void updateUser(UserDetails user)
 * 删除用户账号 : void deleteUser(String username)
 * 修改用户账号密码 : void changePassword(String oldPassword, String newPassword)
 * 判断用户账号是否存在 : boolean userExists(String username)
 * <p>
 * UserDetailsService接口的扩展，提供创建和更新用户信息
 * An extension of the {@link UserDetailsService} which provides the ability to create new
 * users and update existing ones.
 *
 * @author Luke Taylor
 * @since 2.0
 */
public interface UserDetailsManager extends UserDetailsService {

	/**
	 * 创建一个用户
	 * Create a new user with the supplied details.
	 */
	void createUser(UserDetails user);

	/**
	 * 更新用户
	 * Update the specified user.
	 */
	void updateUser(UserDetails user);

	/**
	 * 删除用户
	 * Remove the user with the given login name from the system.
	 */
	void deleteUser(String username);

	/**
	 * 修改用户密码
	 * Modify the current user's password. This should change the user's password in the
	 * persistent user repository (datbase, LDAP etc).
	 *
	 * @param oldPassword current password (for re-authentication if required)
	 * @param newPassword the password to change to
	 */
	void changePassword(String oldPassword, String newPassword);

	/**
	 * 查询用户是否存在
	 * Check if a user with the supplied login name exists in the system.
	 */
	boolean userExists(String username);

}
