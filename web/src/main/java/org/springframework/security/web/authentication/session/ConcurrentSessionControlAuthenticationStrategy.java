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
package org.springframework.security.web.authentication.session;

import java.util.Comparator;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.util.Assert;

/**
 * 用来处理session的并发问题
 * Strategy which handles concurrent session-control.
 *
 * <p>
 * When invoked following an authentication, it will check whether the user in question
 * should be allowed to proceed, by comparing the number of sessions they already have
 * active with the configured <tt>maximumSessions</tt> value. The {@link SessionRegistry}
 * is used as the source of data on authenticated users and session data.
 * </p>
 * <p>
 * If a user has reached the maximum number of permitted sessions, the behaviour depends
 * on the <tt>exceptionIfMaxExceeded</tt> property. The default behaviour is to expire
 * any sessions that exceed the maximum number of permitted sessions, starting with the
 * least recently used sessions. The expired sessions will be invalidated by the
 * {@link ConcurrentSessionFilter} if accessed again. If <tt>exceptionIfMaxExceeded</tt>
 * is set to <tt>true</tt>, however, the user will be prevented from starting a new
 * authenticated session.
 * </p>
 * <p>
 * This strategy can be injected into both the {@link SessionManagementFilter} and
 * instances of {@link AbstractAuthenticationProcessingFilter} (typically
 * {@link UsernamePasswordAuthenticationFilter}), but is typically combined with
 * {@link RegisterSessionAuthenticationStrategy} using
 * {@link CompositeSessionAuthenticationStrategy}.
 * </p>
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @see CompositeSessionAuthenticationStrategy
 * @since 3.2
 */
public class ConcurrentSessionControlAuthenticationStrategy implements
		MessageSourceAware, SessionAuthenticationStrategy {
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private final SessionRegistry sessionRegistry;
	private boolean exceptionIfMaximumExceeded = false;
	private int maximumSessions = 1;

	/**
	 * @param sessionRegistry the session registry which should be updated when the
	 *                        authenticated session is changed.
	 */
	public ConcurrentSessionControlAuthenticationStrategy(SessionRegistry sessionRegistry) {
		Assert.notNull(sessionRegistry, "The sessionRegistry cannot be null");
		this.sessionRegistry = sessionRegistry;
	}

	/**
	 * In addition to the steps from the superclass, the sessionRegistry will be updated
	 * with the new session information.
	 */
	public void onAuthentication(Authentication authentication,
			HttpServletRequest request, HttpServletResponse response) {

		//获取所有的SessionInformation
		//首先调用 sessionRegistry.getAllSessions 方法获取当前用户的所有 session，该方法在调用时，传递两个参数，一个是当前用户的 authentication，另一个参数 false 表示不包含已经过期的
		// session（在用户登录成功后，会将用户的 sessionid 存起来，其中 key 是用户的主体（principal），value 则是该主题对应的 sessionid 组成的一个集合）。
		final List<SessionInformation> sessions = sessionRegistry.getAllSessions(
				authentication.getPrincipal(), false);

		//对session数量进行比对
		//接下来计算出当前用户已经有几个有效 session 了，同时获取允许的 session 并发数。
		int sessionCount = sessions.size();
		int allowedSessions = getMaximumSessionsForThisUser(authentication);
//如果当前 session 数（sessionCount）小于 session 并发数（allowedSessions），则不做任何处理；如果 allowedSessions 的值为 -1，表示对 session 数量不做任何限制。
		if (sessionCount < allowedSessions) {
			// They haven't got too many login sessions running at present
			return;
		}

		if (allowedSessions == -1) {
			// We permit unlimited logins
			return;
		}

		//session数量和允许数量相同
		//如果当前 session 数（sessionCount）等于 session 并发数（allowedSessions），那就先看看当前 session 是否不为 null，并且已经存在于 sessions 中了，如果已经存在了，那都是自家人，
		// 不做任何处理；如果当前 session 为 null，那么意味着将有一个新的 session 被创建出来，届时当前 session 数（sessionCount）就会超过 session 并发数（allowedSessions）。
		if (sessionCount == allowedSessions) {
			HttpSession session = request.getSession(false);

			if (session != null) {
				// Only permit it though if this request is associated with one of the
				// already registered sessions
				for (SessionInformation si : sessions) {
					if (si.getSessionId().equals(session.getId())) {
						return;
					}
				}
			}
			// If the session is null, a new one will be created by the parent class,
			// exceeding the allowed number
		}
//如果前面的代码中都没能 return 掉，那么将进入策略判断方法 allowableSessionsExceeded 中。
		//allowableSessionsExceeded 方法中，首先会有 exceptionIfMaximumExceeded 属性，这就是我们在 SecurityConfig 中配置的 maxSessionsPreventsLogin 的值，默认为 false，如果为 true，就直接抛出异常，
		// 那么这次登录就失败了（对应 2.2 小节的效果），如果为 false，则对 sessions 按照请求时间进行排序，然后再使多余的 session 过期即可
		allowableSessionsExceeded(sessions, allowedSessions, sessionRegistry);
	}

	/**
	 * Method intended for use by subclasses to override the maximum number of sessions
	 * that are permitted for a particular authentication. The default implementation
	 * simply returns the <code>maximumSessions</code> value for the bean.
	 *
	 * @param authentication to determine the maximum sessions for
	 * @return either -1 meaning unlimited, or a positive integer to limit (never zero)
	 */
	protected int getMaximumSessionsForThisUser(Authentication authentication) {
		return maximumSessions;
	}

	/**
	 * 允许子类在检测到太多会话时自定义行为。
	 * Allows subclasses to customise behaviour when too many sessions are detected.
	 *
	 * @param sessions          either <code>null</code> or all unexpired sessions associated with
	 *                          the principal
	 * @param allowableSessions the number of concurrent sessions the user is allowed to
	 *                          have
	 * @param registry          an instance of the <code>SessionRegistry</code> for subclass use
	 */
	protected void allowableSessionsExceeded(List<SessionInformation> sessions,
			int allowableSessions, SessionRegistry registry)
			throws SessionAuthenticationException {
		if (exceptionIfMaximumExceeded || (sessions == null)) {
			throw new SessionAuthenticationException(messages.getMessage(
					"ConcurrentSessionControlAuthenticationStrategy.exceededAllowed",
					new Object[]{allowableSessions},
					"Maximum sessions of {0} for this principal exceeded"));
		}

		// Determine least recently used sessions, and mark them for invalidation
		sessions.sort(Comparator.comparing(SessionInformation::getLastRequest));
		int maximumSessionsExceededBy = sessions.size() - allowableSessions + 1;
		List<SessionInformation> sessionsToBeExpired = sessions.subList(0, maximumSessionsExceededBy);
		for (SessionInformation session : sessionsToBeExpired) {
			session.expireNow();
		}
	}

	/**
	 * Sets the <tt>exceptionIfMaximumExceeded</tt> property, which determines whether the
	 * user should be prevented from opening more sessions than allowed. If set to
	 * <tt>true</tt>, a <tt>SessionAuthenticationException</tt> will be raised which means
	 * the user authenticating will be prevented from authenticating. if set to
	 * <tt>false</tt>, the user that has already authenticated will be forcibly logged
	 * out.
	 *
	 * @param exceptionIfMaximumExceeded defaults to <tt>false</tt>.
	 */
	public void setExceptionIfMaximumExceeded(boolean exceptionIfMaximumExceeded) {
		this.exceptionIfMaximumExceeded = exceptionIfMaximumExceeded;
	}

	/**
	 * Sets the <tt>maxSessions</tt> property. The default value is 1. Use -1 for
	 * unlimited sessions.
	 *
	 * @param maximumSessions the maximimum number of permitted sessions a user can have
	 *                        open simultaneously.
	 */
	public void setMaximumSessions(int maximumSessions) {
		Assert.isTrue(
				maximumSessions != 0,
				"MaximumLogins must be either -1 to allow unlimited logins, or a positive integer to specify a maximum");
		this.maximumSessions = maximumSessions;
	}

	/**
	 * Sets the {@link MessageSource} used for reporting errors back to the user when the
	 * user has exceeded the maximum number of authentications.
	 */
	public void setMessageSource(MessageSource messageSource) {
		Assert.notNull(messageSource, "messageSource cannot be null");
		this.messages = new MessageSourceAccessor(messageSource);
	}
}
