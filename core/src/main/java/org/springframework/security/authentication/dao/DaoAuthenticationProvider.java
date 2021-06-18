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

package org.springframework.security.authentication.dao;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.util.Assert;

/**
 * 用于从UserDetailsService检索用户信息,并进行用户名和密码校验
 * An {@link AuthenticationProvider} implementation that retrieves user details from a
 * {@link UserDetailsService}.
 *
 * @author Ben Alex
 * @author Rob Winch
 */
public class DaoAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {
	// ~ Static fields/initializers
	// =====================================================================================

	/**
	 * The plaintext password used to perform
	 * PasswordEncoder#matches(CharSequence, String)}  on when the user is
	 * not found to avoid SEC-2056.
	 */
	private static final String USER_NOT_FOUND_PASSWORD = "userNotFoundPassword";

	// ~ Instance fields
	// ================================================================================================
	//密码匹配器
	private PasswordEncoder passwordEncoder;

	/**
	 * The password used to perform
	 * {@link PasswordEncoder#matches(CharSequence, String)} on when the user is
	 * not found to avoid SEC-2056. This is necessary, because some
	 * {@link PasswordEncoder} implementations will short circuit if the password is not
	 * in a valid format.
	 */
	private volatile String userNotFoundEncodedPassword;

	//用户获取账户信息
	private UserDetailsService userDetailsService;
	//用于更新用户密码的接口
	private UserDetailsPasswordService userDetailsPasswordService;

	/**
	 * 在 DaoAuthenticationProvider 创建之时，就指定了 PasswordEncoder，似乎并没有用到我们一开始配置的 Bean？其实不是的！
	 * 在 DaoAuthenticationProvider 创建之时，会制定一个默认的 PasswordEncoder，如果我们没有配置任何 PasswordEncoder，将使用这个默认的 PasswordEncoder，如果我们自定义了 PasswordEncoder 实例，
	 * 那么会使用我们自定义的 PasswordEncoder 实例！
	 */
	public DaoAuthenticationProvider() {
		//设置默认的密码编码实现类
		setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
	}

	// ~ Methods
	// ========================================================================================================

	/**
	 * 完成密码的比对
	 * 还需要完成 UsernamePasswordAuthenticationToken 和 UserDetails 密码的比对，这便是交给 additionalAuthenticationChecks 方法完成的，如果这个 void 方法没有抛异常，则认为比对成功
	 *
	 * @param userDetails    as retrieved from the
	 *                       {@link #retrieveUser(String, UsernamePasswordAuthenticationToken)} or
	 *                       <code>UserCache</code>
	 * @param authentication the current request that needs to be authenticated
	 * @throws AuthenticationException
	 */
	@SuppressWarnings("deprecation")
	protected void additionalAuthenticationChecks(UserDetails userDetails,
			UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException {
		//相当于获取密码信息
		if (authentication.getCredentials() == null) {
			logger.debug("Authentication failed: no credentials provided");

			throw new BadCredentialsException(messages.getMessage(
					"AbstractUserDetailsAuthenticationProvider.badCredentials",
					"Bad credentials"));
		}
		//获取存在的密码
		String presentedPassword = authentication.getCredentials().toString();
		//完成密码校验，默认使用懒加载，LazyPasswordEncoder进行密码校验
		if (!passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
			logger.debug("Authentication failed: password does not match stored value");

			throw new BadCredentialsException(messages.getMessage(
					"AbstractUserDetailsAuthenticationProvider.badCredentials",
					"Bad credentials"));
		}
	}

	protected void doAfterPropertiesSet() {
		Assert.notNull(this.userDetailsService, "A UserDetailsService must be set");
	}

	/**
	 * 在 Spring Security 中。提交的用户名和密码，被封装成了 UsernamePasswordAuthenticationToken，而根据用户名加载用户的任务则是交给了 UserDetailsService，
	 * 在 DaoAuthenticationProvider 中，对应的方法便是 retrieveUser，虽然有两个参数，
	 * 但是 retrieveUser 只有第一个参数起主要作用，返回一个 UserDetails。
	 *
	 * @param username       The username to retrieve
	 * @param authentication The authentication request, which subclasses <em>may</em>
	 *                       need to perform a binding-based retrieval of the <code>UserDetails</code>
	 * @return
	 * @throws AuthenticationException
	 */
	protected final UserDetails retrieveUser(String username,
			UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException {
		//防止计时攻击
		prepareTimingAttackProtection();
		try {
			//根据用户名加载用户信息
			UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username);
			if (loadedUser == null) {
				throw new InternalAuthenticationServiceException(
						"UserDetailsService returned null, which is an interface contract violation");
			}
			return loadedUser;
		} catch (UsernameNotFoundException ex) {
			mitigateAgainstTimingAttack(authentication);
			throw ex;
		} catch (InternalAuthenticationServiceException ex) {
			throw ex;
		} catch (Exception ex) {
			throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
		}
	}

	/**
	 * //创建一个成功的身份验证对象。受保护的子类可以覆盖。
	 * //子类通常会在返回的Authentication对象中存储用户提供的原始凭证（不是salted或编码的密码）。
	 * <p>
	 * 比如创建一个UsernamePasswordAuthenticationToken
	 *
	 * @param principal      that should be the principal in the returned object (defined by
	 *                       the {@link #isForcePrincipalAsString()} method)
	 * @param authentication that was presented to the provider for validation
	 * @param user           that was loaded by the implementation
	 * @return
	 */
	@Override
	protected Authentication createSuccessAuthentication(Object principal,
			Authentication authentication, UserDetails user) {
		boolean upgradeEncoding = this.userDetailsPasswordService != null
				&& this.passwordEncoder.upgradeEncoding(user.getPassword());
		//判断是否更新密码
		if (upgradeEncoding) {
			String presentedPassword = authentication.getCredentials().toString();
			String newPassword = this.passwordEncoder.encode(presentedPassword);
			//修改用户的密码
			user = this.userDetailsPasswordService.updatePassword(user, newPassword);
		}
		return super.createSuccessAuthentication(principal, authentication, user);
	}

	/**
	 * 防止攻击
	 * 具体是怎么做的呢？假设 spring security 从数据库中没有查到用户信息就直接抛出异常了，没有去执行 mitigateagainsttimingattack 方法，那么黑客经过大量的测试，再经过统计分析，
	 * 就会发现有一些登录验证耗时明显少于其他登录，进而推断出登录验证时间较短的都是不存在的用户，而登录耗时较长的是数据库中存在的用户。
	 */
	private void prepareTimingAttackProtection() {
		if (this.userNotFoundEncodedPassword == null) {
			this.userNotFoundEncodedPassword = this.passwordEncoder.encode(USER_NOT_FOUND_PASSWORD);
		}
	}

	private void mitigateAgainstTimingAttack(UsernamePasswordAuthenticationToken authentication) {
		if (authentication.getCredentials() != null) {
			String presentedPassword = authentication.getCredentials().toString();
			this.passwordEncoder.matches(presentedPassword, this.userNotFoundEncodedPassword);
		}
	}

	/**
	 * 设置PasswordEncoder实例，如果没有设置，则采用如下获取
	 * Sets the PasswordEncoder instance to be used to encode and validate passwords. If
	 * not set, the password will be compared using {@link PasswordEncoderFactories#createDelegatingPasswordEncoder()}
	 *
	 * @param passwordEncoder must be an instance of one of the {@code PasswordEncoder}
	 *                        types.
	 */
	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		Assert.notNull(passwordEncoder, "passwordEncoder cannot be null");
		this.passwordEncoder = passwordEncoder;
		this.userNotFoundEncodedPassword = null;
	}

	protected PasswordEncoder getPasswordEncoder() {
		return passwordEncoder;
	}

	/**
	 * 设置UserDetailsService
	 *
	 * @param userDetailsService
	 */
	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	protected UserDetailsService getUserDetailsService() {
		return userDetailsService;
	}

	/**
	 * 设置用户的userDetailsPasswordService
	 *
	 * @param userDetailsPasswordService
	 */
	public void setUserDetailsPasswordService(
			UserDetailsPasswordService userDetailsPasswordService) {
		this.userDetailsPasswordService = userDetailsPasswordService;
	}
}
