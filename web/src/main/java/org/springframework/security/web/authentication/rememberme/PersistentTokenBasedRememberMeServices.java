/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.web.authentication.rememberme;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.util.Assert;

/**
 * {@link RememberMeServices} implementation based on Barry Jaspan's <a
 * href="http://jaspan.com/improved_persistent_login_cookie_best_practice">Improved
 * Persistent Login Cookie Best Practice</a>.
 * <p>
 * There is a slight modification to the described approach, in that the username is not
 * stored as part of the cookie but obtained from the persistent store via an
 * implementation of {@link PersistentTokenRepository}. The latter should place a unique
 * constraint on the series identifier, so that it is impossible for the same identifier
 * to be allocated to two different users.
 *
 * <p>
 * User management such as changing passwords, removing users and setting user status
 * should be combined with maintenance of the user's persistent tokens.
 * </p>
 *
 * <p>
 * Note that while this class will use the date a token was created to check whether a
 * presented cookie is older than the configured <tt>tokenValiditySeconds</tt> property
 * and deny authentication in this case, it will not delete these tokens from storage. A
 * suitable batch process should be run periodically to remove expired tokens from the
 * database.
 * </p>
 *
 * @author Luke Taylor
 * @since 2.0
 */
public class PersistentTokenBasedRememberMeServices extends AbstractRememberMeServices {

	private PersistentTokenRepository tokenRepository = new InMemoryTokenRepositoryImpl();
	private SecureRandom random;

	public static final int DEFAULT_SERIES_LENGTH = 16;
	public static final int DEFAULT_TOKEN_LENGTH = 16;

	private int seriesLength = DEFAULT_SERIES_LENGTH;
	private int tokenLength = DEFAULT_TOKEN_LENGTH;

	public PersistentTokenBasedRememberMeServices(String key,
			UserDetailsService userDetailsService,
			PersistentTokenRepository tokenRepository) {
		super(key, userDetailsService);
		random = new SecureRandom();
		this.tokenRepository = tokenRepository;
	}

	/**
	 * Locates the presented cookie data in the token repository, using the series id. If
	 * the data compares successfully with that in the persistent store, a new token is
	 * generated and stored with the same series. The corresponding cookie value is set on
	 * the response.
	 *
	 * @param cookieTokens the series and token values
	 * @throws RememberMeAuthenticationException if there is no stored token corresponding
	 *                                           to the submitted cookie, or if the token in the persistent store has expired.
	 * @throws InvalidCookieException            if the cookie doesn't have two tokens as expected.
	 * @throws CookieTheftException              if a presented series value is found, but the stored
	 *                                           token is different from the one presented.
	 */
	protected UserDetails processAutoLoginCookie(String[] cookieTokens,
			HttpServletRequest request, HttpServletResponse response) {

		if (cookieTokens.length != 2) {
			throw new InvalidCookieException("Cookie token did not contain " + 2
					+ " tokens, but contained '" + Arrays.asList(cookieTokens) + "'");
		}
//首先从前端传来的 cookie 中解析出 series 和 token。
		final String presentedSeries = cookieTokens[0];
		final String presentedToken = cookieTokens[1];
//根据 series 从数据库中查询出一个 PersistentRememberMeToken 实例。
		PersistentRememberMeToken token = tokenRepository
				.getTokenForSeries(presentedSeries);

		if (token == null) {
			// No series match, so we can't authenticate using this cookie
			throw new RememberMeAuthenticationException(
					"No persistent token found for series id: " + presentedSeries);
		}

		// We have a match for this user/series combination
		//如果查出来的 token 和前端传来的 token 不相同，说明账号可能被人盗用（别人用你的令牌登录之后，token 会变）。此时根据用户名移除相关的 token，相当于必须要重新输入用户名密码登录才能获取新的自动登录权限。
		if (!presentedToken.equals(token.getTokenValue())) {
			// Token doesn't match series value. Delete all logins for this user and throw
			// an exception to warn them.
			tokenRepository.removeUserTokens(token.getUsername());

			throw new CookieTheftException(
					messages.getMessage(
							"PersistentTokenBasedRememberMeServices.cookieStolen",
							"Invalid remember-me token (Series/token) mismatch. Implies previous cookie theft attack."));
		}

		//接下来校验 token 是否过期
		if (token.getDate().getTime() + getTokenValiditySeconds() * 1000L < System
				.currentTimeMillis()) {
			throw new RememberMeAuthenticationException("Remember-me login has expired");
		}

		// Token also matches, so login is valid. Update the token value, keeping the
		// *same* series number.
		if (logger.isDebugEnabled()) {
			logger.debug("Refreshing persistent login token for user '"
					+ token.getUsername() + "', series '" + token.getSeries() + "'");
		}
//构造新的 PersistentRememberMeToken 对象，并且更新数据库中的 token（这就是我们文章开头说的，新的会话都会对应一个新的 token）。
		PersistentRememberMeToken newToken = new PersistentRememberMeToken(
				token.getUsername(), token.getSeries(), generateTokenData(), new Date());

		try {
			//将新的令牌重新添加到 cookie 中返回。
			tokenRepository.updateToken(newToken.getSeries(), newToken.getTokenValue(),
					newToken.getDate());
			//根据用户名查询用户信息，再走一波登录流程。
			addCookie(newToken, request, response);
		} catch (Exception e) {
			logger.error("Failed to update token: ", e);
			throw new RememberMeAuthenticationException(
					"Autologin failed due to data access problem");
		}

		return getUserDetailsService().loadUserByUsername(token.getUsername());
	}

	/**
	 * 创建具有新序列号的新永久登录令牌，
	 * Creates a new persistent login token with a new series number, stores the data in
	 * the persistent token repository and adds the corresponding cookie to the response.
	 */
	protected void onLoginSuccess(HttpServletRequest request,
			HttpServletResponse response, Authentication successfulAuthentication) {
		//在登录成功后，首先还是获取到用户名，即 username。
		String username = successfulAuthentication.getName();

		logger.debug("Creating new persistent login for user " + username);
//接下来构造一个 PersistentRememberMeToken 实例，generateSeriesData 和 generateTokenData 方法分别用来获取 series 和 token，具体的生成过程实际上就是调用 SecureRandom 生成随机数再进行 Base64 编码，
// 不同于我们以前用的 Math.random 或者 java.util.Random 这种伪随机数，SecureRandom 则采用的是类似于密码学的随机数生成规则，其输出结果较难预测，适合在登录这样的场景下使用。
		PersistentRememberMeToken persistentToken = new PersistentRememberMeToken(
				username, generateSeriesData(), generateTokenData(), new Date());
		try {
			//调用 tokenRepository 实例中的 createNewToken 方法，tokenRepository 实际上就是我们一开始配置的 JdbcTokenRepositoryImpl，所以这行代码实际上就是将 PersistentRememberMeToken 存入数据库中。
			tokenRepository.createNewToken(persistentToken);
			//最后 addCookie，大家可以看到，就是添加了 series 和 token。
			addCookie(persistentToken, request, response);
		} catch (Exception e) {
			logger.error("Failed to save persistent token ", e);
		}
	}

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) {
		super.logout(request, response, authentication);

		if (authentication != null) {
			tokenRepository.removeUserTokens(authentication.getName());
		}
	}

	/**
	 * 生成一个seriesdata
	 *
	 * @return
	 */
	protected String generateSeriesData() {
		byte[] newSeries = new byte[seriesLength];
		random.nextBytes(newSeries);
		return new String(Base64.getEncoder().encode(newSeries));
	}

	/**
	 * 生成一个token
	 *
	 * @return
	 */
	protected String generateTokenData() {
		byte[] newToken = new byte[tokenLength];
		random.nextBytes(newToken);
		return new String(Base64.getEncoder().encode(newToken));
	}

	/**
	 * 将持久令牌放入到cookie中
	 *
	 * @param token
	 * @param request
	 * @param response
	 */
	private void addCookie(PersistentRememberMeToken token, HttpServletRequest request,
			HttpServletResponse response) {
		setCookie(new String[]{token.getSeries(), token.getTokenValue()},
				getTokenValiditySeconds(), request, response);
	}

	public void setSeriesLength(int seriesLength) {
		this.seriesLength = seriesLength;
	}

	public void setTokenLength(int tokenLength) {
		this.tokenLength = tokenLength;
	}

	@Override
	public void setTokenValiditySeconds(int tokenValiditySeconds) {
		Assert.isTrue(tokenValiditySeconds > 0,
				"tokenValiditySeconds must be positive for this implementation");
		super.setTokenValiditySeconds(tokenValiditySeconds);
	}
}
