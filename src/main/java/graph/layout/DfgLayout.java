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
package graph.layout;

import java.util.Comparator;
import java.util.List;

import edu.uci.ics.jung.visualization.renderers.Renderer.EdgeLabel;
import graph.dfg.DfgEdge;
import graph.dfg.DfgGraph;
import graph.dfg.DfgVertex;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.AbstractVisualGraphLayout;

/**
 * A {@link DfgGraphPlugin} layout that can be used to apply existing Jung
 * layouts.
 */
public class DfgLayout extends AbstractReverseFlowChartLayout<DfgVertex, DfgEdge> {

	public DfgLayout(DfgGraph graph) {
		super(graph, new _DfgEdgeComp(), false);
	}

	private static class _DfgEdgeComp implements Comparator<DfgEdge> {
		@Override
		public int compare(DfgEdge e1, DfgEdge e2) {
			return e1.getArgnum().compareTo(e2.getArgnum());
		}
	}

	@Override
	protected List<DfgVertex> getRoots(VisualGraph<DfgVertex, DfgEdge> g) {
		if (g instanceof DfgGraph dg)
			return dg.getFinVertices();
		return null;
	}

	@Override
	public AbstractVisualGraphLayout<DfgVertex, DfgEdge> createClonedLayout(
			VisualGraph<DfgVertex, DfgEdge> newGraph) {
		return new DfgLayout((DfgGraph) newGraph);
	}

	@Override
	public EdgeLabel<DfgVertex, DfgEdge> getEdgeLabelRenderer() {
		return new DfgLabelRender<>(1);
	}
}
