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
package org.springframework.security.config.annotation;

import java.util.ArrayList;
import java.util.List;

import org.springframework.core.GenericTypeResolver;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;

/**
 * https://andyboke.blog.csdn.net/article/details/90736539
 * 安全配置处理器，允许子类实现该方法
 * SecurityConfigurerAdapter是Spring Security Config对概念模型接口SecurityConfigurer所提供的缺省实现。它作为一个基类存在，开发人员想实现一个SecurityConfigurer时，可以继承自SecurityConfigurerAdapter,然后仅仅覆盖实现其中感兴趣的方法。具体来讲,SecurityConfigurerAdapter提供了如下功能:
 * <p>
 * SecurityConfigurer接口所定义的方法的缺省实现
 * #init
 * #configure
 * 设置和获取所要被配置的安全构建器
 * #setBuilder
 * #getBuilder
 * 设置配置过程中对新建安全对象的后置处理器
 * #addObjectPostProcessor
 * 链式配置构建的支持方法
 * #and
 * A base class for {@link SecurityConfigurer} that allows subclasses to only implement
 * the methods they are interested in. It also provides a mechanism for using the
 * {@link SecurityConfigurer} and when done gaining access to the {@link SecurityBuilder}
 * that is being configured.
 *
 * @param <O> The Object being built by B
 * @param <B> The Builder that is building O and is configured by
 *            {@link SecurityConfigurerAdapter}
 * @author Rob Winch
 * @author Wallace Wadge
 */
public abstract class SecurityConfigurerAdapter<O, B extends SecurityBuilder<O>>
		implements SecurityConfigurer<O, B> {
	private B securityBuilder;

	// 配置过程中新建的安全对象的后置处理器，该对象是多个ObjectPostProcessor的组合
	// 缺省情况下该后置处理器中不包含任何 ObjectPostProcessor
	private CompositeObjectPostProcessor objectPostProcessor = new CompositeObjectPostProcessor();

	/**
	 * 初始化操作
	 *
	 * @param builder
	 * @throws Exception
	 */
	public void init(B builder) throws Exception {
	}

	public void configure(B builder) throws Exception {
	}

	/**
	 * 用于支持链式构建，返回目标构建器
	 * Return the {@link SecurityBuilder} when done using the {@link SecurityConfigurer}.
	 * This is useful for method chaining.
	 *
	 * @return the {@link SecurityBuilder} for further customizations
	 */
	public B and() {
		return getBuilder();
	}

	/**
	 * 获取securityBuilder，更多的是HttpSecurity
	 * Gets the {@link SecurityBuilder}. Cannot be null.
	 *
	 * @return the {@link SecurityBuilder}
	 * @throws IllegalStateException if {@link SecurityBuilder} is null
	 */
	protected final B getBuilder() {
		if (securityBuilder == null) {
			throw new IllegalStateException("securityBuilder cannot be null");
		}
		return securityBuilder;
	}

	/**
	 * Performs post processing of an object. The default is to delegate to the
	 * {@link ObjectPostProcessor}.
	 *
	 * @param object the Object to post process
	 * @return the possibly modified Object to use
	 */
	@SuppressWarnings("unchecked")
	protected <T> T postProcess(T object) {
		return (T) this.objectPostProcessor.postProcess(object);
	}

	/**
	 * 添加ObjectPostProcessor到SecurityConfigurerAdapter
	 * Adds an {@link ObjectPostProcessor} to be used for this
	 * {@link SecurityConfigurerAdapter}. The default implementation does nothing to the
	 * object.
	 *
	 * @param objectPostProcessor the {@link ObjectPostProcessor} to use
	 */
	public void addObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
		this.objectPostProcessor.addObjectPostProcessor(objectPostProcessor);
	}

	/**
	 * 设置SecurityBuilder
	 * Sets the {@link SecurityBuilder} to be used. This is automatically set when using
	 * {@link AbstractConfiguredSecurityBuilder#apply(SecurityConfigurerAdapter)}
	 *
	 * @param builder the {@link SecurityBuilder} to set
	 */
	public void setBuilder(B builder) {
		this.securityBuilder = builder;
	}

	/**
	 * 嵌套类，使用组合模式实现了接口 ObjectPostProcessor，用于组合多个 ObjectPostProcessor，
	 * 当使用该组合对象对目标对象进行后置处理时，其实是使用所组合的每个 ObjectPostProcessor 依次
	 * 对目标对象进行后置处理
	 * An {@link ObjectPostProcessor} that delegates work to numerous
	 * {@link ObjectPostProcessor} implementations.
	 *
	 * @author Rob Winch
	 */
	private static final class CompositeObjectPostProcessor implements
			ObjectPostProcessor<Object> {
		private List<ObjectPostProcessor<?>> postProcessors = new ArrayList<>();

		@SuppressWarnings({"rawtypes", "unchecked"})
		public Object postProcess(Object object) {
			for (ObjectPostProcessor opp : postProcessors) {
				Class<?> oppClass = opp.getClass();
				Class<?> oppType = GenericTypeResolver.resolveTypeArgument(oppClass,
						ObjectPostProcessor.class);
				if (oppType == null || oppType.isAssignableFrom(object.getClass())) {
					object = opp.postProcess(object);
				}
			}
			return object;
		}

		/**
		 * 添加，并进行排序
		 * Adds an {@link ObjectPostProcessor} to use
		 *
		 * @param objectPostProcessor the {@link ObjectPostProcessor} to add
		 * @return true if the {@link ObjectPostProcessor} was added, else false
		 */
		private boolean addObjectPostProcessor(
				ObjectPostProcessor<?> objectPostProcessor) {
			boolean result = this.postProcessors.add(objectPostProcessor);
			postProcessors.sort(AnnotationAwareOrderComparator.INSTANCE);
			return result;
		}
	}
}
