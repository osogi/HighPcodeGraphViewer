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
import graph.layout.SampleGraphFlowChartLayoutProvider;
import ghidra.framework.plugintool.*;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.layout.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link ComponentProvider} that is the UI component of the
 * {@link SampleGraphPlugin}. This shows a graph of the plugins in the system.
 */
public class SampleGraphProvider extends ComponentProviderAdapter {

	/* package */ static final String NAME = "Sample Graph";
	/* package */ static final String RELAYOUT_GRAPH_ACTION_NAME = "Relayout Graph";

	private SampleGraphPlugin plugin;
	private JPanel mainPanel;
	private JComponent component;

	private SampleGraph graph;
	private VisualGraphView<SampleVertex, SampleEdge, SampleGraph> view;
	private LayoutProvider<SampleVertex, SampleEdge, SampleGraph> layoutProvider;

	private HighFunction currentFunction;
	private Program currentProgram;
	private ProgramLocation currentLocation;

	void clear() {
		currentProgram = null;
		currentLocation = null;
	}

	public SampleGraphProvider(PluginTool tool, SampleGraphPlugin plugin) {
		super(tool, NAME, plugin.getName());

		this.plugin = plugin;

		addToTool();
		createActions();

		buildComponent();
	}

	public void updateFunction(HighFunction targetFunction, Program prog) {
		this.currentProgram = prog;
		this.currentFunction = targetFunction;
		installGraph();
	}

	private void installGraph() {
		if (graph != null) {
			// TODO: it was in original plugin but it crush with it.
			// graph.dispose();
		}

		buildGraph();

		if (graph != null) {
			view.setLayoutProvider(layoutProvider);
			view.setGraph(graph);
		}
	}

	void dispose() {
		removeFromTool();
	}

	@Override
	public void componentShown() {
		installGraph();
	}

	private void buildComponent() {

		view = new VisualGraphView<>();

		// these default to off; they are typically controlled via a UI element; the
		// values set here are arbitrary and are for demo purposes
		view.setVertexFocusPathHighlightMode(PathHighlightMode.OUT);
		view.setVertexHoverPathHighlightMode(PathHighlightMode.IN);

		installTooltipProvider();

		component = view.getViewComponent();

		mainPanel = new JPanel(new BorderLayout());

		mainPanel.add(component, BorderLayout.CENTER);
	}

	private void installTooltipProvider() {

//		VertexTooltipProvider<SampleVertex, SampleEdge> tooltipProvider = new VertexTooltipProvider<>() {
//
//			@Override
//			public JComponent getTooltip(SampleVertex v) {
//				JToolTip tip = new JToolTip();
//				tip.setTipText(getTooltipText(v, v.getName()));
//				return tip;
//			}
//
//			@Override
//			public JComponent getTooltip(SampleVertex v, SampleEdge e) {
//				boolean isStart = e.getStart() == v;
//				String prefix;
//				if (isStart) {
//					prefix = "From: " + v.getName();
//				} else {
//					prefix = "To: " + v.getName();
//				}
//
//				String text = getTooltipText(v, prefix);
//				JToolTip tip = new JToolTip();
//				tip.setTipText(text);
//				return tip;
//			}
//
//			@Override
//			public String getTooltipText(SampleVertex v, MouseEvent e) {
//				return getTooltipText(v, v.getName());
//			}
//
//			private String getTooltipText(SampleVertex v, String title) {
//				return "<html>" + title;// + "<br><hr><br>" + v.getText();
//			}
//		};
//		view.setTooltipProvider(tooltipProvider);
	}

	private void buildGraph() {

//		Map<Class<?>, SampleVertex> pluginToVertices = new HashMap<>();
//
//		List<Plugin> plugins = tool.getManagedPlugins();
//		for (Plugin p : plugins) {
//			SampleVertex vertex = new SampleVertex(p.getName());
//			graph.addVertex(vertex);
//			pluginToVertices.put(p.getClass(), vertex);
//		}
//
//		for (Plugin p : plugins) {
//			SampleVertex from = pluginToVertices.get(p.getClass());
//
//			StringBuilder names = new StringBuilder();
//			List<Class<?>> dependencies = p.getPluginDescription().getServicesRequired();
//			for (Class<?> serviceClass : dependencies) {
//				SampleVertex to = locateService(pluginToVertices, serviceClass);
//				if (to != null) {
//					names.append(serviceClass.getSimpleName()).append('\n');
//					graph.addEdge(new SampleEdge(from, to));
//				}
//			}
//
//			from.getTextArea().setText(names.toString());
//		}
		if (currentFunction != null) {
			try {
				graph = GraphFactory.createGraph(currentFunction, TaskMonitor.DUMMY);
				VisualGraphLayout<SampleVertex, SampleEdge> layout = layoutProvider.getLayout(graph, TaskMonitor.DUMMY);
				graph.setLayout(layout);
			} catch (CancelledException e) {
				// can't happen as long as we are using the dummy monitor
			}
		}
	}

	/* package */ SampleGraph getGraph() {
		return graph;
	}

	/* package */ VisualGraphViewUpdater<?, ?> getGraphViewUpdater() {
		GraphViewer<SampleVertex, SampleEdge> viewer = view.getPrimaryGraphViewer();
		VisualGraphViewUpdater<SampleVertex, SampleEdge> updater = viewer.getViewUpdater();
		return updater;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	private void createActions() {

		addLayoutAction();
	}

	private SampleVertex prevSelect;

	void locationChanged(ProgramLocation location) {
		if (this.currentLocation == location)
			return;

		if (prevSelect != null)
			prevSelect.setSelected(false);
		
		this.currentLocation = location;

		Address currentAddress = currentLocation.getAddress();
		
		if (graph == null)
			return;
		
		SampleVertex v = graph.getVertexForAddress(currentAddress);

		if (v == null)
			return;

		v.setSelected(true);
		v.selectByAddress(currentAddress);
		prevSelect = v;
		mainPanel.updateUI();
	}

	// Layouts

	private void addLayoutAction() {

		MultiStateDockingAction<LayoutProvider<SampleVertex, SampleEdge, SampleGraph>> layoutAction = new MultiStateDockingAction<>(
				RELAYOUT_GRAPH_ACTION_NAME, plugin.getName(), KeyBindingType.SHARED) {

			@Override
			public void actionPerformed(ActionContext context) {
				// this callback is when the user clicks the button
				LayoutProvider<SampleVertex, SampleEdge, SampleGraph> currentUserData = getCurrentUserData();
				changeLayout(currentUserData);
			}

			@Override
			public void actionStateChanged(
					ActionState<LayoutProvider<SampleVertex, SampleEdge, SampleGraph>> newActionState,
					EventTrigger trigger) {
				changeLayout(newActionState.getUserData());
			}
		};
		layoutAction.setGroup("B");
		layoutAction.setHelpLocation(SampleGraphPlugin.DEFAULT_HELP);

		addLayoutProviders(layoutAction);

		addLocalAction(layoutAction);
	}

	private void changeLayout(LayoutProvider<SampleVertex, SampleEdge, SampleGraph> provider) {

		this.layoutProvider = provider;
		if (isVisible()) { // this can be called while building--ignore that
			installGraph();
		}
	}

	private void addLayoutProviders(
			MultiStateDockingAction<LayoutProvider<SampleVertex, SampleEdge, SampleGraph>> layoutAction) {

//		// Note: the first state set will be made the current selected value of the
//		// multi action
//		LayoutProvider<SampleVertex, SampleEdge, SampleGraph> provider = new SampleGraphPluginDependencyLayoutProvider();
//		layoutAction.addActionState(new ActionState<>(provider.getLayoutName(), provider.getActionIcon(), provider));

		LayoutProvider provider = new SampleGraphFlowChartLayoutProvider();
		layoutAction.addActionState(new ActionState<>(provider.getLayoutName(), provider.getActionIcon(), provider));

//		//
//		// Add some Jung layouts for users to try
//		//
//		Set<JungLayoutProvider<SampleVertex, SampleEdge, SampleGraph>> jungLayouts = JungLayoutProviderFactory
//				.createLayouts();
//
//		for (JungLayoutProvider<SampleVertex, SampleEdge, SampleGraph> l : jungLayouts) {
//			layoutAction.addActionState(new ActionState<>(l.getLayoutName(), l.getActionIcon(), l));
//		}
	}

	private class GraphFactory {
		private static boolean isEntry(CodeBlock codeBlock) {
			boolean isSource = true;
			try {
				CodeBlockReferenceIterator iter = codeBlock.getSources(TaskMonitor.DUMMY);
				while (iter.hasNext()) {
					isSource = false;
					if (iter.next().getFlowType().isCall()) {
						// any calls into a code block will make it an 'entry'
						return true;
					}
				}
			} catch (CancelledException e) {
				// will never happen, because I don't have a monitor
			}
			return isSource;
		}

		private static SampleGraph createGraph(HighFunction function, TaskMonitor monitor) throws CancelledException {

			BidiMap<PcodeBlockBasic, SampleVertex> vertices = createVertices(function, monitor);

			Collection<SampleEdge> edges = createdEdges(vertices, monitor);

//			FunctionGraphVertexAttributes settings = new FunctionGraphVertexAttributes(controller.getProgram());

			SampleGraph graph = new SampleGraph(function, vertices.values(), edges);

			SampleVertex functionEntryVertex = graph.getVertexForAddress(function.getFunction().getEntryPoint());

			if (functionEntryVertex == null) {
				functionEntryVertex = graph.getNextVertexForAddress(function.getFunction().getEntryPoint());
			}

			graph.setRootVertex(functionEntryVertex);

//			for (FGVertex vertex : vertices.values()) {
//				vertex.setVertexType(getVertexType(graph, vertex));
//			}

			return graph;
		}

		private static Collection<SampleEdge> createdEdges(BidiMap<PcodeBlockBasic, SampleVertex> vertices,
				TaskMonitor monitor) throws CancelledException {

			List<SampleEdge> edges = new ArrayList<>();
			for (SampleVertex startVertex : vertices.values()) {
				Collection<SampleEdge> vertexEdges = getEdgesForStartVertex(vertices, startVertex, monitor);

				edges.addAll(vertexEdges);
			}

			return edges;
		}

		private static Collection<SampleEdge> getEdgesForStartVertex(
				BidiMap<PcodeBlockBasic, SampleVertex> blockToVertexMap, SampleVertex startVertex, TaskMonitor monitor)
				throws CancelledException {

			List<SampleEdge> edges = new ArrayList<>();
			PcodeBlockBasic codeBlock = blockToVertexMap.getKey(startVertex);

			int outSize = codeBlock.getOutSize();
			for (int i = 0; i < outSize; i++) {
				PcodeBlockBasic destinationBlock = (PcodeBlockBasic) codeBlock.getOut(i);
				SampleVertex destinationVertex = blockToVertexMap.get(destinationBlock);
				if (destinationVertex == null) {
					continue;// no vertex means the code block is not in our function
				}

				edges.add(new SampleEdge(startVertex, destinationVertex));
			}
			return edges;
		}

		private static BidiMap<PcodeBlockBasic, SampleVertex> createVertices(HighFunction hfunction,
				TaskMonitor monitor) throws CancelledException {

			BidiMap<PcodeBlockBasic, SampleVertex> vertices = new DualHashBidiMap<>();

			ArrayList<PcodeBlockBasic> bbs = hfunction.getBasicBlocks();

			Function fun = hfunction.getFunction();
//			CodeBlockModel blockModel = new BasicBlockModel(SampleGraphProvider.this.currentProgram);

			for (PcodeBlockBasic bb : bbs) {
				Address adr = bb.getFirstOp().getSeqnum().getTarget();
//				boolean isEntry = isEntry(blockModel.getCodeBlockAt(adr, monitor));

				SampleVertex v = new SampleVertex(adr.toString(), bb);
				vertices.put(bb, v);
			}

			return vertices;

		}

	}

}
