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

import java.awt.BorderLayout;

import java.util.*;
import javax.swing.*;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.*;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.*;
import graph.layout.CfgFlowChartLayoutProvider;
import ghidra.framework.plugintool.*;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.layout.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link ComponentProvider} that is the UI component of the
 * {@link HighPcodeGraphViewerPlugin}. This shows the High P-Code graph for the current function.
 */
public class HighPcodeGraphViewerProvider extends ComponentProviderAdapter {

	/* package */ static final String NAME = "High P-Code Graph";
	/* package */ static final String RELAYOUT_GRAPH_ACTION_NAME = "Relayout Graph";

	private HighPcodeGraphViewerPlugin plugin;
	private JPanel mainPanel;
	private JComponent component;

	private CfgGraph graph;
	private VisualGraphView<CfgVertex, CfgEdge, CfgGraph> view;
	private LayoutProvider<CfgVertex, CfgEdge, CfgGraph> layoutProvider;
	private HighFunction installedFunction;

	private HighFunction currentFunction;
	@SuppressWarnings("unused")
	private Program currentProgram;
	@SuppressWarnings("unused")
	private ProgramLocation currentLocation;

	void clear() {
		currentProgram = null;
		currentLocation = null;
		currentFunction = null;
		installedFunction = null;
		graph = null;
	}

	public HighPcodeGraphViewerProvider(PluginTool tool, HighPcodeGraphViewerPlugin plugin) {
		super(tool, NAME, plugin.getName());

		this.plugin = plugin;

		addToTool();
		createActions();

		buildComponent();
	}

	public void updateFunction(HighFunction targetFunction, Program prog) {
		this.currentProgram = prog;
		this.currentFunction = targetFunction;
		if (isVisible()) {
			installGraph(false);
		}
	}

	private void installGraph(boolean force) {
		if (currentFunction == null) {
			return;
		}

		if (!force && graph != null && currentFunction == installedFunction) {
			return;
		}

		if (graph != null) {
			// Disposing the graph here can destabilize the embedded graph view.
			// graph.dispose();
		}

		buildGraph();

		if (graph != null) {
			view.setLayoutProvider(layoutProvider);
			view.setGraph(graph);
			installedFunction = currentFunction;
		}
	}

	void dispose() {
		removeFromTool();
	}

	@Override
	public void componentShown() {
		installGraph(false);
	}

	private void buildComponent() {

		view = new VisualGraphView<>();

		// these default to off; they are typically controlled via a UI element; the
		// values set here are arbitrary and are for demo purposes
		view.setVertexFocusPathHighlightMode(PathHighlightMode.OUT);
		view.setVertexHoverPathHighlightMode(PathHighlightMode.IN);

		component = view.getViewComponent();

		mainPanel = new JPanel(new BorderLayout());

		mainPanel.add(component, BorderLayout.CENTER);
	}

	private void buildGraph() {
		if (currentFunction != null) {
			try {
				if (layoutProvider == null) {
					layoutProvider = new CfgFlowChartLayoutProvider();
				}
				graph = GraphFactory.createGraph(currentFunction, TaskMonitor.DUMMY);
				VisualGraphLayout<CfgVertex, CfgEdge> layout =
					layoutProvider.getLayout(graph, TaskMonitor.DUMMY);
				graph.setLayout(layout);
			}
			catch (CancelledException e) {
				// can't happen as long as we are using the dummy monitor
			}
		}
	}

	/* package */ CfgGraph getGraph() {
		return graph;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	private void createActions() {
		addLayoutAction();
	}

	// Layouts

	private void addLayoutAction() {

		MultiStateDockingAction<LayoutProvider<CfgVertex, CfgEdge, CfgGraph>> layoutAction =
			new MultiStateDockingAction<>(
				RELAYOUT_GRAPH_ACTION_NAME, plugin.getName(), KeyBindingType.SHARED) {

				@Override
				public void actionPerformed(ActionContext context) {
					// this callback is when the user clicks the button
					LayoutProvider<CfgVertex, CfgEdge, CfgGraph> currentUserData =
						getCurrentUserData();
					changeLayout(currentUserData);
				}

				@Override
				public void actionStateChanged(
						ActionState<LayoutProvider<CfgVertex, CfgEdge, CfgGraph>> newActionState,
						EventTrigger trigger) {
					changeLayout(newActionState.getUserData());
				}
			};

		addLayoutProviders(layoutAction);

		addLocalAction(layoutAction);
	}

	private void changeLayout(LayoutProvider<CfgVertex, CfgEdge, CfgGraph> provider) {

		this.layoutProvider = provider;
		if (isVisible()) { // this can be called while building--ignore that
			installGraph(true);
		}
	}

	private void addLayoutProviders(
			MultiStateDockingAction<LayoutProvider<CfgVertex, CfgEdge, CfgGraph>> layoutAction) {

		LayoutProvider<CfgVertex, CfgEdge, CfgGraph> provider =
			new CfgFlowChartLayoutProvider();
		layoutProvider = provider;
		layoutAction.addActionState(
			new ActionState<>(provider.getLayoutName(), provider.getActionIcon(), provider));

	}

	private class GraphFactory {
//		private static boolean isEntry(CodeBlock codeBlock) {
//			boolean isSource = true;
//			try {
//				CodeBlockReferenceIterator iter = codeBlock.getSources(TaskMonitor.DUMMY);
//				while (iter.hasNext()) {
//					isSource = false;
//					if (iter.next().getFlowType().isCall()) {
//						// any calls into a code block will make it an 'entry'
//						return true;
//					}
//				}
//			}
//			catch (CancelledException e) {
//				// will never happen, because I don't have a monitor
//			}
//			return isSource;
//		}

		private static CfgGraph createGraph(HighFunction function, TaskMonitor monitor)
				throws CancelledException {

			BidiMap<PcodeBlockBasic, CfgVertex> vertices = createVertices(function, monitor);

			Collection<CfgEdge> edges = createEdges(vertices, monitor);

			CfgGraph graph = new CfgGraph(function, vertices.values(), edges);

			CfgVertex functionEntryVertex =
				graph.getVertexForAddress(function.getFunction().getEntryPoint());

			if (functionEntryVertex == null) {
				functionEntryVertex =
					graph.getNextVertexForAddress(function.getFunction().getEntryPoint());
			}

			graph.setRootVertex(functionEntryVertex);

			return graph;
		}

		private static Collection<CfgEdge> createEdges(
				BidiMap<PcodeBlockBasic, CfgVertex> vertices,
				TaskMonitor monitor) throws CancelledException {

			List<CfgEdge> edges = new ArrayList<>();
			for (CfgVertex startVertex : vertices.values()) {
				Collection<CfgEdge> vertexEdges =
					getEdgesForStartVertex(vertices, startVertex, monitor);

				edges.addAll(vertexEdges);
			}

			return edges;
		}

		@SuppressWarnings("unused")
		private static Collection<CfgEdge> getEdgesForStartVertex(
				BidiMap<PcodeBlockBasic, CfgVertex> blockToVertexMap, CfgVertex startVertex,
				TaskMonitor monitor)
				throws CancelledException {

			List<CfgEdge> edges = new ArrayList<>();
			PcodeBlockBasic codeBlock = blockToVertexMap.getKey(startVertex);

			int outSize = codeBlock.getOutSize();
			for (int i = 0; i < outSize; i++) {
				PcodeBlockBasic destinationBlock = (PcodeBlockBasic) codeBlock.getOut(i);
				CfgVertex destinationVertex = blockToVertexMap.get(destinationBlock);
				if (destinationVertex == null) {
					continue;// no vertex means the code block is not in our function
				}

				edges.add(new CfgEdge(startVertex, destinationVertex));
			}
			return edges;
		}

		@SuppressWarnings("unused")
		private static BidiMap<PcodeBlockBasic, CfgVertex> createVertices(HighFunction hfunction,
				TaskMonitor monitor) throws CancelledException {
			BidiMap<PcodeBlockBasic, CfgVertex> vertices = new DualHashBidiMap<>();

			ArrayList<PcodeBlockBasic> bbs = hfunction.getBasicBlocks();

			for (PcodeBlockBasic bb : bbs) {
				Address adr = bb.getStart();
				if (adr == null && bb.getFirstOp() != null) {
					adr = bb.getFirstOp().getSeqnum().getTarget();
				}
				if (adr == null) {
					continue;
				}
				CfgVertex v = new CfgVertex(adr.toString(), bb);
				vertices.put(bb, v);
			}

			return vertices;

		}

	}

	public void selectionChanged(ProgramSelection sel) {
		if (graph == null) {
			return;
		}

		HashSet<CfgVertex> verts = new HashSet<>();
		if (sel != null) {
			for (AddressRange r : sel.getAddressRanges()) {
				verts.addAll(graph.getVerticesForRange(r));
			}
		}

		verts.removeIf(v -> !v.selectionChanged(sel));
		verts.forEach(v -> v.setForceSelection(true));
		view.getGraphComponent().setVerticesSelected(verts);
		verts.forEach(v -> v.setForceSelection(false));
	}

}
