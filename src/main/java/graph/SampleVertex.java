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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

import edu.uci.ics.jung.visualization.RenderContext;
import ghidra.graph.viewer.GraphViewer;
import ghidra.graph.viewer.VisualGraphView;
import ghidra.graph.viewer.layout.LayoutProvider;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.ProgramSelection;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import graph.dfg.DfgEdge;
import graph.dfg.DfgGraph;
import graph.dfg.DfgVertex;
import graph.dfg.PcodeVertex;
import graph.dfg.VarnodeVertex;
import graph.layout.DfgLayoutProvider;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A vertex for the {@link SampleGraphPlugin}
 */
public class SampleVertex extends GraphViewVisualVertex<DfgVertex, DfgEdge, DfgGraph>
		implements Comparable<SampleVertex> {
	private DfgGraph graph;

	public PcodeBlockBasic hBasicBlock;
	public Address startAddress;
	public Address endAddress;

	private static DfgGraph buildGraph(PcodeBlockBasic hBasicBlock) {
		DfgGraph graph = new DfgGraph();

		Iterator<PcodeOp> pcodes = hBasicBlock.getIterator();
		Map<Varnode, DfgVertex> varVerts = new HashMap<>();

		while (pcodes.hasNext()) {
			PcodeOp pcode = pcodes.next();

			DfgVertex pVert = new PcodeVertex(pcode.getMnemonic(), pcode);
			graph.addVertex(pVert);

			Integer i = 0;
			for (Varnode vi : pcode.getInputs()) {
				DfgVertex viVert = varVerts.get(vi);
				if (viVert == null) {
					viVert = new VarnodeVertex(vi.toString(), vi);
					varVerts.put(vi, viVert);
				}

				graph.addVertex(viVert);
				graph.addEdge(new DfgEdge(viVert, pVert, i++));
			}

			Varnode vo = pcode.getOutput();
			if (vo != null) {
				DfgVertex voVert = varVerts.get(vo);
				if (voVert == null) {
					voVert = new VarnodeVertex(vo.toString(), vo);
					varVerts.put(vo, voVert);
				}
				graph.addVertex(voVert);
				graph.addEdge(new DfgEdge(pVert, voVert, null));
			}
		}

		return graph;
	}

	private static void setupRender(VisualGraphView<DfgVertex, DfgEdge, DfgGraph> graphView) {
		GraphViewer<DfgVertex, DfgEdge> viewer = graphView.getPrimaryGraphViewer();

		RenderContext<DfgVertex, DfgEdge> renderContext = viewer.getRenderContext();
		com.google.common.base.Function<DfgEdge, String> edgeLabelTransformer = e -> e.getLabel();
		renderContext.setEdgeLabelTransformer(edgeLabelTransformer);
	}

	private static VisualGraphView<DfgVertex, DfgEdge, DfgGraph> buildGraphView(
			PcodeBlockBasic hBasicBlock) {
		VisualGraphView<DfgVertex, DfgEdge, DfgGraph> graphView = new VisualGraphView<>();

		LayoutProvider<DfgVertex, DfgEdge, DfgGraph> lp = new DfgLayoutProvider();
		graphView.setLayoutProvider(lp);

		DfgGraph graph = buildGraph(hBasicBlock);
		try {
			VisualGraphLayout<DfgVertex, DfgEdge> l = lp.getLayout(graph, TaskMonitor.DUMMY);
//			EdgeLabel<DfgVertex, DfgEdge> p = l.getEdgeLabelRenderer();
			graph.setLayout(l);
		}
		catch (CancelledException e) {
			// can't happen as long as we are using the dummy monitor
		}
		graphView.setGraph(graph);

		setupRender(graphView);

		return graphView;
	}

	public SampleVertex(String name, PcodeBlockBasic hbb) {
		super(name, buildGraphView(hbb));
		hBasicBlock = hbb;
		graph = graphView.getVisualGraph();
		startAddress = hBasicBlock.getStart();
		endAddress = hBasicBlock.getStop();
	}

	@Override
	public int compareTo(SampleVertex other) {
		return startAddress.compareTo(other.startAddress);
	}

	private boolean forceSelection;

	public void setForceSelection(boolean value) {
		forceSelection = value;
	}

	@Override
	public void setSelected(boolean selected) {
		super.setSelected(selected);
		if ((selected == false) && (!forceSelection)) {
			graph.clearSelectedVertices();
		}
	}

	/**
	 *
	 * @param sel
	 * @return is any inner vertices selected
	 */
	public boolean selectionChanged(ProgramSelection sel) {
		Iterator<AddressRange> subSel = sel.intersectRange(startAddress, endAddress).iterator();

		HashSet<DfgVertex> verts = new HashSet<>();

		while (subSel.hasNext()) {
			AddressRange r = subSel.next();
			verts.addAll(graph.getVerticesForRange(r));
		}

		graphView.getGraphComponent().setVerticesSelected(verts);

		return !verts.isEmpty();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((hBasicBlock == null) ? 0 : hBasicBlock.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		SampleVertex other = (SampleVertex) obj;
		if (hBasicBlock == null) {
			if (other.hBasicBlock != null) {
				return false;
			}
		}
		else if (!hBasicBlock.equals(other.hBasicBlock)) {
			return false;
		}
		return true;
	}
}
