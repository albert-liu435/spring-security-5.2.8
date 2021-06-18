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

package org.springframework.security.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * https://andyboke.blog.csdn.net/article/details/90201594
 * Spring Security中AuthenticationProvider接口抽象建模了认证提供者这一概念，某个认证提供者能认证符合某种特征的认证令牌Authentication。
 * <p>
 * Spring Security针对常见的一些场景提供了AuthenticationProvider实现，比如RemoteAuthenticationProvider,DaoAuthenticationProvider,JaasAuthenticationProvider等等。
 * <p>
 * 在Spring Security中，AuthenticationProvider通常的用法是交由ProviderManager统一管理和应用。ProviderManager是一个AuthenticationManager实现，它会被广泛应用于认证认证令牌对象Authentication,但实际上具体的认证工作是委托给了ProviderManager所管理的一组AuthenticationProvider上。
 * AuthenticationProvider 最最最常用的一个实现便是 DaoAuthenticationProvider。顾名思义，Dao 正是数据访问层的缩写，也暗示了这个身份认证器的实现思路
 * <p>
 * <p>
 * authenticate 方法用来做验证，就是验证用户身份。
 * supports 则用来判断当前的 AuthenticationProvider 是否支持对应的 Authentication。
 * <p>
 * Indicates a class can process a specific
 * {@link org.springframework.security.core.Authentication} implementation.
 *
 * @author Ben Alex
 */
public interface AuthenticationProvider {
	// ~ Methods
	// ========================================================================================================


	//使用与AuthenticationManager.authenticate（身份验证）相同的协议执行身份验证。
	//返回：完全身份验证的对象，包括凭据。 如果AuthenticationProvider无法支持对传递的Authentication对象的身份验证，则可能返回null。
	//在这种情况下，将尝试支持所呈现的Authentication类的下一个AuthenticationProvider。
	//如果如果身份验证失败抛出AuthenticationException

	/**
	 * Performs authentication with the same contract as
	 * {@link org.springframework.security.authentication.AuthenticationManager#authenticate(Authentication)}
	 * .
	 *
	 * @param authentication the authentication request object.
	 * @return a fully authenticated object including credentials. May return
	 * <code>null</code> if the <code>AuthenticationProvider</code> is unable to support
	 * authentication of the passed <code>Authentication</code> object. In such a case,
	 * the next <code>AuthenticationProvider</code> that supports the presented
	 * <code>Authentication</code> class will be tried.
	 * @throws AuthenticationException if authentication fails.
	 */
	Authentication authenticate(Authentication authentication)
			throws AuthenticationException;

	//如果此AuthenticationProvider支持指示的Authentication对象，则返回true。
	//返回true并不能保证AuthenticationProvider能够验证所呈现的Authentication类的实例。
	//它只是表明它可以支持对它进行更密切的评估。 AuthenticationProvider仍然可以从authenticate（Authentication）方法返回null，
	//以指示应该尝试另一个AuthenticationProvider。
	//选择能够执行身份验证的AuthenticationProvider是在运行时ProviderManager进行的

	/**
	 * Returns <code>true</code> if this <Code>AuthenticationProvider</code> supports the
	 * indicated <Code>Authentication</code> object.
	 * <p>
	 * Returning <code>true</code> does not guarantee an
	 * <code>AuthenticationProvider</code> will be able to authenticate the presented
	 * instance of the <code>Authentication</code> class. It simply indicates it can
	 * support closer evaluation of it. An <code>AuthenticationProvider</code> can still
	 * return <code>null</code> from the {@link #authenticate(Authentication)} method to
	 * indicate another <code>AuthenticationProvider</code> should be tried.
	 * </p>
	 * <p>
	 * Selection of an <code>AuthenticationProvider</code> capable of performing
	 * authentication is conducted at runtime the <code>ProviderManager</code>.
	 * </p>
	 *
	 * @param authentication
	 * @return <code>true</code> if the implementation can more closely evaluate the
	 * <code>Authentication</code> class presented
	 */
	boolean supports(Class<?> authentication);
}
