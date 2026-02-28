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

import java.util.Collection;
import java.util.Collections;

import generic.theme.GColor;
import ghidra.graph.viewer.vertex.DockingVisualVertex;
import ghidra.program.model.address.Address;

/**
 * A vertex for the {@link SampleGraphPlugin}
 */
public class DfgVertex extends DockingVisualVertex {

	public enum VertexType {
		VARNODE, PCODE
	}

	public VertexType vertexType;

	public Collection<Address> getAssociatedAddresses() {
		return Collections.emptyList();
	}

	public DfgVertex(String name, VertexType vt) {
		super(name);

		vertexType = vt;

		if (vt == VertexType.VARNODE) {
			getTextArea().setBackground(new GColor("color.graph.dfg.varnode"));
		}
		else if (vt == VertexType.PCODE) {
			getTextArea().setBackground(new GColor("color.graph.dfg.pcode"));
		}
	}
}
