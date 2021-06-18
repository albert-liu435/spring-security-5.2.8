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

package org.springframework.security.core.session;

import java.util.List;

/**
 * 维护SessionInformation的注册表
 * Maintains a registry of <code>SessionInformation</code> instances.
 *
 * @author Ben Alex
 */
public interface SessionRegistry {
	// ~ Methods
	// ========================================================================================================

	/**
	 * 获取所有的已知的Principals
	 * Obtains all the known principals in the <code>SessionRegistry</code>.
	 *
	 * @return each of the unique principals, which can then be presented to
	 * {@link #getAllSessions(Object, boolean)}.
	 */
	List<Object> getAllPrincipals();

	/**
	 * 获取特定principal的所有的SessionInformation
	 * Obtains all the known sessions for the specified principal. Sessions that have been
	 * destroyed are not returned. Sessions that have expired may be returned, depending
	 * on the passed argument.
	 *
	 * @param principal              to locate sessions for (should never be <code>null</code>)
	 * @param includeExpiredSessions if <code>true</code>, the returned sessions will also
	 *                               include those that have expired for the principal
	 * @return the matching sessions for this principal (should not return null).
	 */
	List<SessionInformation> getAllSessions(Object principal,
			boolean includeExpiredSessions);

	/**
	 * 获取SessionInformation
	 * Obtains the session information for the specified <code>sessionId</code>. Even
	 * expired sessions are returned (although destroyed sessions are never returned).
	 *
	 * @param sessionId to lookup (should never be <code>null</code>)
	 * @return the session information, or <code>null</code> if not found
	 */
	SessionInformation getSessionInformation(String sessionId);

	/**
	 * 刷新最后的请求
	 * Updates the given <code>sessionId</code> so its last request time is equal to the
	 * present date and time. Silently returns if the given <code>sessionId</code> cannot
	 * be found or the session is marked to expire.
	 *
	 * @param sessionId for which to update the date and time of the last request (should
	 *                  never be <code>null</code>)
	 */
	void refreshLastRequest(String sessionId);

	/**
	 * 注册新的session
	 * Registers a new session for the specified principal. The newly registered session
	 * will not be marked for expiration.
	 *
	 * @param sessionId to associate with the principal (should never be <code>null</code>
	 *                  )
	 * @param principal to associate with the session (should never be <code>null</code>)
	 */
	void registerNewSession(String sessionId, Object principal);

	/**
	 * 根据sessionidSessionInformation
	 * Deletes all the session information being maintained for the specified
	 * <code>sessionId</code>. If the <code>sessionId</code> is not found, the method
	 * gracefully returns.
	 *
	 * @param sessionId to delete information for (should never be <code>null</code>)
	 */
	void removeSessionInformation(String sessionId);
}
