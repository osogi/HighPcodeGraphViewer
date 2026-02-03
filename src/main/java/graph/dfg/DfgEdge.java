/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package graph.dfg;

import ghidra.graph.viewer.edge.AbstractVisualEdge;

/**
 * An edge for the {@link SampleGraph}
 */
public class DfgEdge extends AbstractVisualEdge<DfgVertex> {

	
	private Integer argNum;
	
	public DfgEdge(DfgVertex start, DfgVertex end, Integer number) {
		super(start, end);
		argNum = number;
	}

	@SuppressWarnings("unchecked")
	// Suppressing warning on the return type; we know our class is the right type
	@Override
	public DfgEdge cloneEdge(DfgVertex start, DfgVertex end) {
		return new DfgEdge(start, end, argNum);
	}

	public String getLabel() {
		if (argNum != null) {
			return argNum.toString();
		}
		
		return null;
		
	}
}
