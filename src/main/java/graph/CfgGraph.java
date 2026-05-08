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

import datastructures.Interval;
import datastructures.IntervalSetTree;
import ghidra.graph.graphs.DefaultVisualGraph;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.pcode.HighFunction;

/**
 * A graph for the {@link HighPcodeGraphViewerPlugin} that allows for filtering
 */
public class CfgGraph extends DefaultVisualGraph<CfgVertex, CfgEdge> {

	private VisualGraphLayout<CfgVertex, CfgEdge> layout;
	private HighFunction targetHFunction;
	private CfgVertex rootVertex;

	public CfgVertex getRootVertex() {
		return rootVertex;
	}

	public void setRootVertex(CfgVertex v) {
		rootVertex = v;
	}

	private class VertexInterval implements Interval {

		private long start;
		private long end;
		public CfgVertex vert;

		public VertexInterval(CfgVertex v) {
			super();
			start = v.startAddress.getUnsignedOffset();
			end = v.endAddress.getUnsignedOffset() + 1;
			vert = v;
		}

		public VertexInterval(long s, long e) {
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

		@Override
		public boolean equals(Object obj) {
			if (obj == null) {
				return false;
			}

			if (obj.getClass() != this.getClass()) {
				return false;
			}

			VertexInterval other = (VertexInterval) obj;
			if (vert == null) {
				return other.vert == null;
			}
			return vert.equals(other.vert);
		}

		@Override
		public int hashCode() {
			return vert == null ? 0 : vert.hashCode();
		}
	}

	IntervalSetTree<VertexInterval> sortedVertices;

	@Override
	protected void verticesAdded(Collection<CfgVertex> added) {
		super.verticesAdded(added);
		for (CfgVertex v : added) {
			sortedVertices.insert(new VertexInterval(v));
		}
	}

	@Override
	protected void verticesRemoved(Collection<CfgVertex> removed) {
		super.verticesRemoved(removed);
		for (CfgVertex v : removed) {
			sortedVertices.delete(new VertexInterval(v));
		}
	}

	public CfgGraph(HighFunction function, Set<CfgVertex> pvertices,
			Collection<CfgEdge> pedges) {
		super();
		sortedVertices = new IntervalSetTree<>();

		for (CfgVertex v : pvertices) {
			addVertex(v);
		}

		for (CfgEdge e : pedges) {
			addEdge(e);
		}

		targetHFunction = function;
	}

	public CfgVertex getNextVertexForAddress(Address address) {
		CfgVertex resVert = null;
		Address minAddr = null;
		for (CfgVertex v : getVertices()) {
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

	public CfgVertex getVertexForAddress(Address address) {
		return getVertexForAddress(address, Collections.emptySet());
	}

	public CfgVertex getVertexForAddress(Address address, Collection<CfgVertex> ignore) {

		for (CfgVertex v : getVertices()) {
			if (v.hBasicBlock.contains(address) && !ignore.contains(v)) {
				return v;
			}
		}

		return null;
	}

	public HashSet<CfgVertex> getVerticesForRange(AddressRange addrRange) {
		Iterator<VertexInterval> it = sortedVertices.overlappers(new VertexInterval(
			addrRange.getMinAddress().getUnsignedOffset(),
			addrRange.getMaxAddress().getUnsignedOffset()));

		HashSet<CfgVertex> res = new HashSet<>();
		while (it.hasNext()) {
			res.add(it.next().vert);
		}
		return res;
	}

	@Override
	public VisualGraphLayout<CfgVertex, CfgEdge> getLayout() {
		return layout;
	}

	@Override
	public CfgGraph copy() {
		CfgGraph newGraph = new CfgGraph(targetHFunction, vertices.keySet(), edges.keySet());

		return newGraph;
	}

	void setLayout(VisualGraphLayout<CfgVertex, CfgEdge> layout) {
		this.layout = layout;
	}
}
