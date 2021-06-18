/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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
 * https://andyboke.blog.csdn.net/article/details/90644865
 * UserDetailsService是Spring Security提供的一个概念模型接口，用于抽象建模系统提供这样一种服务能力:管理用户详情。
 * <p>
 * UserDetailsService只定义了一个方法UserDetails loadUserByUsername(String username) throws UsernameNotFoundException，声明通过用户名username可以获取用户详情UserDetails,如果对应用户名username的用户记录(一般也称作用户账号)不存在，则抛出异常UsernameNotFoundException。
 * <p>
 * 注意方法loadUserByUsername的具体实现在比较用户名时可以大小写区分也可以大小写不区分，具体怎么做留给实现者决定。
 * <p>
 * 方法loadUserByUsername如果找到一个用户记录的话会返回一个可序列化的UserDetails对象，它包含如下信息 :
 * <p>
 * 用户名
 * 账号是否过期
 * 账号是否被锁定
 * 账号安全凭证(通常意义上指的就是的密码)是否过期
 * 账号是否被禁用
 * 所赋予的权限集合
 * <p>
 * <p>
 * <p>
 * https://www.jianshu.com/p/078c16f110d8
 * 用户获取账户信息的核心接口
 * UserDetailsSevice就是当前系统中如何获取库存用户信息的服务。
 * <p>
 * <p>
 * 在这里就可以简单的认为，在我们输入用户名和密码之后，框架便会通过UserDetailsService 的实现类去寻找验证用户前端输入的用户名和密码是否正确，如果正确则返回UserDetails完成登录操作。Security模式提供了许多种方式的用户信息管理服务实现，比如基于数据库、基于LDAP的。我们当前使用的是最简单基于内存的用户管理实现InMemoryUserDetailsManager。
 * <p>
 * 作者：AkiraPan
 * 链接：https://www.jianshu.com/p/078c16f110d8
 * 来源：简书
 * 著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。
 * Core interface which loads user-specific data.
 * <p>
 * It is used throughout the framework as a user DAO and is the strategy used by the
 * {@link org.springframework.security.authentication.dao.DaoAuthenticationProvider
 * DaoAuthenticationProvider}.
 *
 * <p>
 * The interface requires only one read-only method, which simplifies support for new
 * data-access strategies.
 *
 * @author Ben Alex
 * @see org.springframework.security.authentication.dao.DaoAuthenticationProvider
 * @see UserDetails
 */
public interface UserDetailsService {
	// ~ Methods
	// ========================================================================================================

	/**
	 * 用于加载用户的信息
	 * //根据用户名找到用户。 在实际实现中，搜索可能区分大小写，或者不区分大小写，具体取决于实现实例的配置方式。
	 * //在这种情况下，返回的UserDetails对象可能具有与实际请求的用户名不同的用户名。
	 * Locates the user based on the username. In the actual implementation, the search
	 * may possibly be case sensitive, or case insensitive depending on how the
	 * implementation instance is configured. In this case, the <code>UserDetails</code>
	 * object that comes back may have a username that is of a different case than what
	 * was actually requested..
	 *
	 * @param username the username identifying the user whose data is required.
	 * @return a fully populated user record (never <code>null</code>)
	 * @throws UsernameNotFoundException if the user could not be found or the user has no
	 *                                   GrantedAuthority
	 */
	UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
