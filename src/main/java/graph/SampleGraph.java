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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import datastructures.Interval;
import datastructures.IntervalTree;
import ghidra.graph.graphs.DefaultVisualGraph;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
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

	private class VertexIntrerval implements Interval {

		private long start;
		private long end;
		public SampleVertex vert;

		public VertexIntrerval(SampleVertex v) {
			super();
			start = v.startAddress.getUnsignedOffset();
			end = v.endAddress.getUnsignedOffset() + 1;
			vert = v;
		}

		public VertexIntrerval(long s, long e) {
			super();
			start = s;
			end = e + 1;
		}

		@Override
		public long start() {
			return start;
		}

		@Override
		public long end() {
			return end;
		}

	}

	IntervalTree<VertexIntrerval> sortedVertices;

	@Override
	protected void verticesAdded(Collection<SampleVertex> added) {
		super.verticesAdded(added);
		for (SampleVertex v : added) {
			sortedVertices.insert(new VertexIntrerval(v));
		}
	}

	@Override
	protected void verticesRemoved(Collection<SampleVertex> removed) {
		super.verticesRemoved(removed);
		for (SampleVertex v : removed) {
			sortedVertices.delete(new VertexIntrerval(v));
		}
	}

	public SampleGraph(HighFunction function, Set<SampleVertex> pvertices, Collection<SampleEdge> pedges) {
		super();
		sortedVertices = new IntervalTree<>();

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

	public HashSet<SampleVertex> getVerticesForRange(AddressRange addrRange) {
		Iterator<VertexIntrerval> it = sortedVertices.overlappers(new VertexIntrerval(
				addrRange.getMinAddress().getUnsignedOffset(), addrRange.getMaxAddress().getUnsignedOffset()));

		HashSet<SampleVertex> res = new HashSet<>();
		while (it.hasNext()) {
			res.add(it.next().vert);
		}
		return res;
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
