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
package org.springframework.security.web.firewall;

/**
 * https://andyboke.blog.csdn.net/article/details/90573633
 * 在我们使用Spring Security开发Spring MVC应用时，有的时候会遇到RequestRejectedException，这时候应该怎么办呢 ?
 * <p>
 * 实际上，RequestRejectedException是Spring Security的防火墙机制抛出的。如果遇到了该异常，开发人员可以从以下几个方面检查是否存在问题 :
 * <p>
 * 请求路径中是否包含./,/../,/.等字符串序列，这些字符串序列会被认为是有安全问题的,从而导致该异常;
 * 请求路径中是否包含连续的两个斜杠//(除了协议部分的//之外)，该字符串序列也会导致该异常;
 * 如果请求路径是浏览器端代码拼装出来的，这个问题可能会经常出现，此时开发人员应该是没有恶意的，但Spring Security防火墙并不能识别这一点，所以一样会拒绝该请求。所以开发人员需要在这里多加留意。否则会可能增加不少开发调试成本。
 * <p>
 * 如果请求路径中包含不可打印ASCII字符则会抛出该异常拒绝该请求;
 * 如果请求URL（无论是URL编码前还是URL编码后)包含了分号(;或者%3b或者%3B)则会抛出该异常拒绝该请求;
 * 如果请求URL（无论是URL编码前还是URL编码后)包含了斜杠(%2f或者%2F)则会抛出该异常拒绝该请求;
 * 如果请求URL（无论是URL编码前还是URL编码后)包含了反斜杠(\或者%5c或者%5B)则会抛出该异常拒绝该请求;
 * 如果请求URL在URL编码后包含了%25(URL编码了的百分号%),或者在URL编码前包含了百分号%则会抛出该异常拒绝该请求;
 * 如果请求URL在URL编码后包含了URL编码的英文句号.(%2e或者%2E)则会抛出该异常拒绝该请求。
 *
 * @author Luke Taylor
 */
public class RequestRejectedException extends RuntimeException {
	public RequestRejectedException(String message) {
		super(message);
	}
}
