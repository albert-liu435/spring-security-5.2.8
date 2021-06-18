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
package org.springframework.security.core;

/**
 * 表明该实例是否包含敏感数据，可以使用{@code eraseCredentials}方法擦除。实现需要在任何内部对象上调用该方法，这些对象也可以实现该接口
 * 只是框架内部使用
 * Indicates that the implementing object contains sensitive data, which can be erased
 * using the {@code eraseCredentials} method. Implementations are expected to invoke the
 * method on any internal objects which may also implement this interface.
 * <p>
 * For internal framework use only. Users who are writing their own
 * {@code AuthenticationProvider} implementations should create and return an appropriate
 * {@code Authentication} object there, minus any sensitive data, rather than using this
 * interface.
 *
 * @author Luke Taylor
 * @since 3.0.3
 */
public interface CredentialsContainer {
	/**
	 * 擦除敏感数据
	 */
	void eraseCredentials();
}
