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

import graph.*;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.AbstractVisualGraphLayout;
import ghidra.app.plugin.core.functiongraph.graph.layout.flowchart.AbstractFlowChartLayout;

/**
 * A {@link HighPcodeGraphViewerPlugin} layout that can be used to apply existing Jung
 * layouts.
 */
public class SampleGraphFlowChartLayout extends AbstractFlowChartLayout<SampleVertex, SampleEdge> {

	public SampleGraphFlowChartLayout(SampleGraph graph) {
		super(graph, new _SampleEdgeComp(), false);
	}

	private static class _SampleEdgeComp implements Comparator<SampleEdge> {
		@Override
		public int compare(SampleEdge e1, SampleEdge e2) {
			return 0;
		}
	}

	@Override
	protected SampleVertex getRoot(VisualGraph<SampleVertex, SampleEdge> g) {
		if (g instanceof SampleGraph sg)
			return sg.getRootVertex();
		return null;
	}

	@Override
	public AbstractVisualGraphLayout<SampleVertex, SampleEdge> createClonedLayout(
			VisualGraph<SampleVertex, SampleEdge> newGraph) {
		return new SampleGraphFlowChartLayout((SampleGraph) newGraph);
	}
}
