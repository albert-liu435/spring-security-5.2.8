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
package org.springframework.security.authentication;

import org.springframework.security.core.AuthenticationException;

/**
 * 由特定用户帐户状态（锁定、禁用等）引起的身份验证异常的基类。
 * Base class for authentication exceptions which are caused by a particular user account
 * status (locked, disabled etc).
 *
 * @author Luke Taylor
 */
public abstract class AccountStatusException extends AuthenticationException {
	public AccountStatusException(String msg) {
		super(msg);
	}

	public AccountStatusException(String msg, Throwable t) {
		super(msg, t);
	}
}
