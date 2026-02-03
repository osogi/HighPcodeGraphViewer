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
import java.util.LinkedList;
import java.util.List;

import ghidra.graph.graphs.DefaultVisualGraph;
import ghidra.graph.viewer.layout.VisualGraphLayout;

/**
 * A graph for the {@link SampleGraphPlugin} that allows for filtering
 */
public class DfgGraph extends DefaultVisualGraph<DfgVertex, DfgEdge> {

	private VisualGraphLayout<DfgVertex, DfgEdge> layout;
//	public List<DfgVertex> finVertices; // leafs, pcode without output; varnode without use in this bb;
	
	public List<DfgVertex> getFinVertices() {
		List<DfgVertex> res = new LinkedList<>();
		Collection<DfgVertex> verts = this.getVertices();
		for (DfgVertex v :verts) {
			if(this.getOutEdges(v).size() == 0) {
				res.add(v);
			}
		}
		return res;
	}
	
	@Override
	public VisualGraphLayout<DfgVertex, DfgEdge> getLayout() {
		return layout;
	}

	@Override
	public DfgGraph copy() {
		DfgGraph newGraph = new DfgGraph();

		for (DfgVertex v : vertices.keySet()) {
			newGraph.addVertex(v);
		}

		for (DfgEdge e : edges.keySet()) {
			newGraph.addEdge(e);
		}

		return newGraph;
	}

	public void setLayout(VisualGraphLayout<DfgVertex, DfgEdge> layout) {
		this.layout = layout;
	}
}
