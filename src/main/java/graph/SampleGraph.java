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
package graph;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import ghidra.graph.graphs.DefaultVisualGraph;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighFunction;

/**
 * A graph for the {@link SampleGraphPlugin} that allows for filtering
 */
public class SampleGraph extends DefaultVisualGraph<SampleVertex, SampleEdge> {

	private VisualGraphLayout<SampleVertex, SampleEdge> layout;
	private HighFunction targetHFunction;
	private SampleVertex rootVertex;

	public SampleVertex getRootVertex() {
		return rootVertex;
	}

	public void setRootVertex(SampleVertex v) {
		rootVertex = v;
	}

	public SampleGraph(HighFunction function, Set<SampleVertex> pvertices, Collection<SampleEdge> pedges) {
		super();

		for (SampleVertex v : pvertices) {
			addVertex(v);
		}

		for (SampleEdge e : pedges) {
			addEdge(e);
		}

		targetHFunction = function;
	}

	public SampleVertex getNextVertexForAddress(Address address) {
		SampleVertex resVert = null;
		Address minAddr = null;
		for (SampleVertex v : getVertices()) {
			Address vAddr = v.hBasicBlock.getStart();
			vAddr.compareTo(address);
			if (vAddr.compareTo(address) > 0) {
				if (minAddr == null || minAddr.compareTo(vAddr) > 0) {
					minAddr = vAddr;
					resVert = v;
				}
			}
		}
		return resVert;
	}

	public SampleVertex getVertexForAddress(Address address) {
		return getVertexForAddress(address, Collections.emptySet());
	}

	public SampleVertex getVertexForAddress(Address address, Collection<SampleVertex> ignore) {

		for (SampleVertex v : getVertices()) {
			if (v.hBasicBlock.contains(address) && !ignore.contains(v)) {
				return v;
			}
		}

		return null;
	}

	@Override
	public VisualGraphLayout<SampleVertex, SampleEdge> getLayout() {
		return layout;
	}

	@Override
	public SampleGraph copy() {
		SampleGraph newGraph = new SampleGraph(targetHFunction, vertices.keySet(), edges.keySet());

		return newGraph;
	}

	void setLayout(VisualGraphLayout<SampleVertex, SampleEdge> layout) {
		this.layout = layout;
	}
}
