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

package org.springframework.security.access.vote;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

/**
 * 最严格的的授权决策器。要求所有 AccessDecisionVoter 均返回肯定的结果时，才代表授予权限。
 * 可以看到，同前两个决策器不同之处在于，循环将每一个当前请求需要的 ConfigAttribute 传递给 AccessDecisionVoter 进行决策，而不是全部传递过去。这就代表每一个  ConfigAttribute 每一个 AccessDecisionVoter 均需返回肯定的结果才可以授予权限。所以，最为严格。
 * <p>
 * <p>
 * 基于一致的决策器。 用户持有的所有角色都同意访问才能放行
 * Simple concrete implementation of
 * {@link org.springframework.security.access.AccessDecisionManager} that requires all
 * voters to abstain or grant access.
 */
public class UnanimousBased extends AbstractAccessDecisionManager {

	public UnanimousBased(List<AccessDecisionVoter<?>> decisionVoters) {
		super(decisionVoters);
	}

	// ~ Methods
	// ========================================================================================================

	/**
	 * This concrete implementation polls all configured {@link AccessDecisionVoter}s for
	 * each {@link ConfigAttribute} and grants access if <b>only</b> grant (or abstain)
	 * votes were received.
	 * <p>
	 * Other voting implementations usually pass the entire list of
	 * <tt>ConfigAttribute</tt>s to the <code>AccessDecisionVoter</code>. This
	 * implementation differs in that each <code>AccessDecisionVoter</code> knows only
	 * about a single <code>ConfigAttribute</code> at a time.
	 * <p>
	 * If every <code>AccessDecisionVoter</code> abstained from voting, the decision will
	 * be based on the {@link #isAllowIfAllAbstainDecisions()} property (defaults to
	 * false).
	 *
	 * @param authentication the caller invoking the method
	 * @param object         the secured object
	 * @param attributes     the configuration attributes associated with the method being
	 *                       invoked
	 * @throws AccessDeniedException if access is denied
	 */
	public void decide(Authentication authentication, Object object,
			Collection<ConfigAttribute> attributes) throws AccessDeniedException {

		int grant = 0;

		List<ConfigAttribute> singleAttributeList = new ArrayList<>(1);
		singleAttributeList.add(null);

		for (ConfigAttribute attribute : attributes) {
			singleAttributeList.set(0, attribute);

			for (AccessDecisionVoter voter : getDecisionVoters()) {
				int result = voter.vote(authentication, object, singleAttributeList);

				if (logger.isDebugEnabled()) {
					logger.debug("Voter: " + voter + ", returned: " + result);
				}

				switch (result) {
					case AccessDecisionVoter.ACCESS_GRANTED:
						grant++;

						break;

					case AccessDecisionVoter.ACCESS_DENIED:
						throw new AccessDeniedException(messages.getMessage(
								"AbstractAccessDecisionManager.accessDenied",
								"Access is denied"));

					default:
						break;
				}
			}
		}

		// To get this far, there were no deny votes
		if (grant > 0) {
			return;
		}

		// To get this far, every AccessDecisionVoter abstained
		checkAllowIfAllAbstainDecisions();
	}
}
