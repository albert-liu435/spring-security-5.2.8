/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.config.annotation.configuration;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.Aware;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.util.Assert;

/**
 * http://www.itboyhub.com/2020/0623/objectpostprocess.html
 * AutowireBeanFactoryObjectPostProcessor 的源码很好理解：
 * <p>
 * 首先在构建 AutowireBeanFactoryObjectPostProcessor 对象时，传入了一个 AutowireCapableBeanFactory 对象，看过 Spring 源码的小伙伴就知道，AutowireCapableBeanFactory 可以帮助我们手动的将一个实例注册到 Spring 容器中。
 * 在 postProcess 方法中，就是具体的注册逻辑了，都很简单，我就不再赘述。
 * 由此可见，ObjectPostProcessor 的主要作用就是手动注册实例到 Spring 容器中去（并且让实例走一遍 Bean 的生命周期）。
 * <p>
 * 正常来说，我们项目中的 Bean 都是通过自动扫描注入到 Spring 容器中去的，然而在 Spring Security 框架中，有大量的代码不是通过自动扫描注入到 Spring 容器中去的，而是直接 new 出来的，这样做的本意是为了简化项目配置。
 * <p>
 * 这些直接 new 出来的代码，如果想被 Spring 容器管理该怎么办呢？那就得 ObjectPostProcessor 出场了。
 * 允许注册对象参与{@link AutowireCapableBeanFactory}对{@link Aware}方法的后期处理
 * Allows registering Objects to participate with an {@link AutowireCapableBeanFactory}'s
 * post processing of {@link Aware} methods, {@link InitializingBean#afterPropertiesSet()}
 * , and {@link DisposableBean#destroy()}.
 *
 * @author Rob Winch
 * @since 3.2
 */
final class AutowireBeanFactoryObjectPostProcessor
		implements ObjectPostProcessor<Object>, DisposableBean, SmartInitializingSingleton {
	private final Log logger = LogFactory.getLog(getClass());
	private final AutowireCapableBeanFactory autowireBeanFactory;
	private final List<DisposableBean> disposableBeans = new ArrayList<>();
	private final List<SmartInitializingSingleton> smartSingletons = new ArrayList<>();

	AutowireBeanFactoryObjectPostProcessor(
			AutowireCapableBeanFactory autowireBeanFactory) {
		Assert.notNull(autowireBeanFactory, "autowireBeanFactory cannot be null");
		this.autowireBeanFactory = autowireBeanFactory;
	}

	/*
	 *初始化方法
	 *  (non-Javadoc)
	 *
	 * @see
	 * org.springframework.security.config.annotation.web.Initializer#initialize(java.
	 * lang.Object)
	 */
	@SuppressWarnings("unchecked")
	public <T> T postProcess(T object) {
		if (object == null) {
			return null;
		}
		T result = null;
		try {
			//初始化给定的Bean
			result = (T) this.autowireBeanFactory.initializeBean(object,
					object.toString());
		} catch (RuntimeException e) {
			Class<?> type = object.getClass();
			throw new RuntimeException(
					"Could not postProcess " + object + " of type " + type, e);
		}
		this.autowireBeanFactory.autowireBean(object);
		if (result instanceof DisposableBean) {
			this.disposableBeans.add((DisposableBean) result);
		}
		if (result instanceof SmartInitializingSingleton) {
			this.smartSingletons.add((SmartInitializingSingleton) result);
		}
		return result;
	}

	/* (non-Javadoc)
	 * @see org.springframework.beans.factory.SmartInitializingSingleton#afterSingletonsInstantiated()
	 */
	@Override
	public void afterSingletonsInstantiated() {
		for (SmartInitializingSingleton singleton : smartSingletons) {
			singleton.afterSingletonsInstantiated();
		}
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.beans.factory.DisposableBean#destroy()
	 */
	public void destroy() {
		for (DisposableBean disposable : this.disposableBeans) {
			try {
				disposable.destroy();
			} catch (Exception error) {
				this.logger.error(error);
			}
		}
	}

}
