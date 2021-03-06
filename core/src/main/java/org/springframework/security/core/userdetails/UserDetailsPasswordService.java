/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.core.userdetails;

/**
 * https://andyboke.blog.csdn.net/article/details/90737741
 * 用于更新用户密码的接口
 * UserDetailsPasswordService是Spring Security从5.1版本开始提供的一个接口。它定义了实现类要提供可以修改用户账号密码的能力。
 * <p>
 * 比如InMemoryUserDetailsManager就实现了接口UserDetailsPasswordService,可以对自己管理的用户账号的密码进行修改。
 * An API for changing a {@link UserDetails} password.
 *
 * @author Rob Winch
 * @since 5.1
 */
public interface UserDetailsPasswordService {

	/**
	 * 修改用户的密码
	 * Modify the specified user's password. This should change the user's password in the
	 * persistent user repository (database, LDAP etc).
	 *
	 * @param user        the user to modify the password for
	 * @param newPassword the password to change to,
	 *                    encoded by the configured {@code PasswordEncoder}
	 * @return the updated UserDetails with the new password
	 */
	UserDetails updatePassword(UserDetails user, String newPassword);
}
