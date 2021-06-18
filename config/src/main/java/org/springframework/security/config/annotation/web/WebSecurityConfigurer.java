/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.config.annotation.web;

import javax.servlet.Filter;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**https://andyboke.blog.csdn.net/article/details/90573895
 * WebSecurityConfigurer是Spring Security Config的一个概念模型接口，用于建模"Web安全配置器"这一概念模型。
 * WebSecurityConfigurer被设计用于配置某个构建目标为Filter的某个SecurityBuilder安全构建器，WebSecurityConfigurer自身并没有定义任何方法，但是它继承自接口SecurityConfigurer,表明这是一个"安全配置器",所以它也具有SecurityConfigurer所具备的初始化能力#init和构建能力#configure。
 * <p>
 * Allows customization to the {@link WebSecurity}. In most instances users will use
 * {@link EnableWebSecurity} and a create {@link Configuration} that extends
 * {@link WebSecurityConfigurerAdapter} which will automatically be applied to the
 * {@link WebSecurity} by the {@link EnableWebSecurity} annotation.
 *
 * @author Rob Winch
 * @see WebSecurityConfigurerAdapter
 * @since 3.2
 */
public interface WebSecurityConfigurer<T extends SecurityBuilder<Filter>> extends
		SecurityConfigurer<Filter, T> {

}
