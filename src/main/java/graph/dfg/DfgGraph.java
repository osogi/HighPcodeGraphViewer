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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.TreeMap;

import ghidra.graph.graphs.DefaultVisualGraph;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import graph.SampleVertex;

/**
 * A graph for the {@link SampleGraphPlugin} that allows for filtering
 */
public class DfgGraph extends DefaultVisualGraph<DfgVertex, DfgEdge> {

	private VisualGraphLayout<DfgVertex, DfgEdge> layout;
	TreeMap<Address, List<DfgVertex>> sortedVertices = new TreeMap<>();

	@Override
	protected void verticesAdded(Collection<DfgVertex> added) {
		super.verticesAdded(added);
		for (DfgVertex v : added) {
			for (Address addr : v.getAssociatedAddresses()) {
				sortedVertices.computeIfAbsent(addr, k -> new ArrayList<>()).add(v);
			}
		}
	}

	@Override
	protected void verticesRemoved(Collection<DfgVertex> removed) {
		super.verticesRemoved(removed);
		for (DfgVertex v : removed) {
			for (Address addr : v.getAssociatedAddresses()) {
				List<DfgVertex> tmp = sortedVertices.get(addr);
				if (tmp != null) {
					tmp.remove(v);
				}
			}
		}
	}
	
	public HashSet<DfgVertex> getVerticesForRange(AddressRange addrRange) {
		Collection<List<DfgVertex>> lists = sortedVertices.subMap(addrRange.getMinAddress(), true, addrRange.getMaxAddress(), true).values();

		HashSet<DfgVertex> res = new HashSet<>();
		for (List<DfgVertex> list : lists) {
			res.addAll(list);
		}
		return res;
	}

	public List<DfgVertex> getFinVertices() { // leafs, pcode without output; varnode without use in this bb;
		List<DfgVertex> res = new LinkedList<>();
		Collection<DfgVertex> verts = this.getVertices();
		for (DfgVertex v : verts) {
			if (this.getOutEdges(v).size() == 0) {
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
