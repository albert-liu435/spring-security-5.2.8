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

package org.springframework.security.access;

/**
 * 是授权异常 AccessDeniedException，授权异常的实现类比较少，因为授权失败的可能原因比较少。
 * Thrown if an {@link org.springframework.security.core.Authentication Authentication}
 * object does not hold a required authority.
 *
 * @author Ben Alex
 */
public class AccessDeniedException extends RuntimeException {
	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>AccessDeniedException</code> with the specified message.
	 *
	 * @param msg the detail message
	 */
	public AccessDeniedException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>AccessDeniedException</code> with the specified message and
	 * root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public AccessDeniedException(String msg, Throwable t) {
		super(msg, t);
	}
}
