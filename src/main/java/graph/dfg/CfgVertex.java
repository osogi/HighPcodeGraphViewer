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

import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.swing.*;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;

import docking.GenericHeader;
import edu.uci.ics.jung.visualization.RenderContext;
import edu.uci.ics.jung.visualization.renderers.Renderer.EdgeLabel;
import generic.theme.GColor;
import ghidra.graph.viewer.GraphViewer;
import ghidra.graph.viewer.VisualGraphView;
import ghidra.graph.viewer.VisualVertex;
import ghidra.graph.viewer.layout.JungLayoutProvider;
import ghidra.graph.viewer.layout.LayoutProvider;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.graph.viewer.renderer.VisualGraphEdgeLabelRenderer;
import ghidra.graph.viewer.vertex.AbstractVisualVertex;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.MathUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import graph.SampleEdge;
import graph.SampleGraph;
import graph.SampleVertex;
import graph.dfg.DfgVertex.VertexType;
import graph.layout.DfgLayoutProvider;

public class CfgVertex extends AbstractVisualVertex {

	private JPanel mainPanel = new JPanel(new BorderLayout());
	LayoutProvider<DfgVertex, DfgEdge, DfgGraph> lp = new DfgLayoutProvider();

	private VisualGraphView<DfgVertex, DfgEdge, DfgGraph> graphView;
	private DfgGraph graph;

	private JComponent workingArea;
	private GenericHeader genericHeader;
	private String name;
	private PcodeBlockBasic hBasicBlock;

	private int maxWidth = 200; // something reasonable

	private void buildGraph() {
		graph = new DfgGraph();

		Iterator<PcodeOp> pcodes = hBasicBlock.getIterator();
		Map<Varnode, DfgVertex> varVerts = new HashMap<>();

		while (pcodes.hasNext()) {
			PcodeOp pcode = pcodes.next();

			DfgVertex pVert = new DfgVertex(pcode.getMnemonic(), VertexType.PCODE);
			graph.addVertex(pVert);

			Integer i = 0;
			for (Varnode vi : pcode.getInputs()) {
				DfgVertex viVert = varVerts.get(vi);
				if (viVert == null) {
					viVert = new DfgVertex(vi.toString(), VertexType.VARNODE);
					varVerts.put(vi, viVert);
				}

				graph.addVertex(viVert);
				graph.addEdge(new DfgEdge(viVert, pVert, i++));
			}

			Varnode vo = pcode.getOutput();
			if (vo != null) {
				DfgVertex voVert = varVerts.get(vo);
				if (voVert == null) {
					voVert = new DfgVertex(vo.toString(), VertexType.VARNODE);
					varVerts.put(vo, voVert);
				}
				graph.addVertex(voVert);
				graph.addEdge(new DfgEdge(pVert, voVert, null));
			}

			graph.setRootVertex(pVert);
		}

		try {
			VisualGraphLayout<DfgVertex, DfgEdge> l = lp.getLayout(graph, TaskMonitor.DUMMY);
			EdgeLabel<DfgVertex, DfgEdge> p = l.getEdgeLabelRenderer();
			graph.setLayout(l);
		} catch (CancelledException e) {
			// can't happen as long as we are using the dummy monitor
		}
	}

	private void setupRender() {
		GraphViewer<DfgVertex, DfgEdge> viewer = graphView.getPrimaryGraphViewer();

		RenderContext<DfgVertex, DfgEdge> renderContext = viewer.getRenderContext();
		com.google.common.base.Function<DfgEdge, String> edgeLabelTransformer = e -> e.getLabel();
		renderContext.setEdgeLabelTransformer(edgeLabelTransformer);

//		VisualGraphEdgeLabelRenderer edgeLabelRenderer = new VisualGraphEdgeLabelRenderer(
//				new GColor("color.black"));
//		edgeLabelRenderer.setNonPickedForegroundColor(new GColor("color.black"));
//		edgeLabelRenderer.setRotateEdgeLabels(false);
//		renderContext.setEdgeLabelRenderer(edgeLabelRenderer);
		
	}

	public CfgVertex(String name, PcodeBlockBasic hbb) {
		this.name = name;
		hBasicBlock = hbb;

		buildGraph();

		graphView = new VisualGraphView<>();


		graphView.setLayoutProvider(lp);
		graphView.setGraph(graph);
		
		setupRender();

		workingArea = graphView.getViewComponent();

//				new JTextArea() {
//			// overridden to cap the width
//			@Override
//			public Dimension getPreferredSize() {
//				Dimension preferredSize = super.getPreferredSize();
//				int width = preferredSize.width;
//				preferredSize.width = MathUtilities.clamp(width, width, maxWidth);
//				return preferredSize;
//			}
//		};
		workingArea.setPreferredSize(new Dimension(200, 50));
		workingArea.setBackground(new GColor("color.bg.visualgraph.dockingvertex"));
		workingArea.setForeground(new GColor("color.fg.visualgraph.dockingvertex"));
		workingArea.setBorder(BorderFactory.createRaisedBevelBorder());

		PropertyChangeListener[] listeners = workingArea.getPropertyChangeListeners();
		for (PropertyChangeListener l : listeners) {

			// the AquaCaret does not remove itself as a listener
			if (l.getClass().getSimpleName().contains("AquaCaret")) {
				workingArea.removePropertyChangeListener(l);
			}
		}

		workingArea.setVisible(true);

		genericHeader = new GenericHeader() {
			// overridden to prevent excessive title bar width for long names
			@Override
			public Dimension getPreferredSize() {
				Dimension preferredSize = super.getPreferredSize();
				int width = workingArea.getPreferredSize().width;
				int preferredWidth = MathUtilities.clamp(width, width, maxWidth);
				if (preferredWidth <= 0) {
					return preferredSize;
				}

				int toolBarWidth = getToolBarWidth();
				int minimumGrabArea = 60;
				int minimumWidth = minimumGrabArea + toolBarWidth;
				preferredSize.width = MathUtilities.clamp(preferredWidth, minimumWidth, maxWidth);
				return preferredSize;
			}
		};
		genericHeader.setComponent(workingArea);
		genericHeader.setTitle(name);
		genericHeader.setNoWrapToolbar(true);

		mainPanel.addKeyListener(new KeyListener() {

			@Override
			public void keyTyped(KeyEvent e) {
				KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
				kfm.redispatchEvent(workingArea, e);
				e.consume(); // consume all events; signal that our text area will handle them
			}

			@Override
			public void keyReleased(KeyEvent e) {
				KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
				kfm.redispatchEvent(workingArea, e);
				e.consume(); // consume all events; signal that our text area will handle them
			}

			@Override
			public void keyPressed(KeyEvent e) {
				KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
				kfm.redispatchEvent(workingArea, e);
				e.consume(); // consume all events; signal that our text area will handle them
			}
		});

		mainPanel.add(genericHeader, BorderLayout.NORTH);
		mainPanel.add(workingArea, BorderLayout.CENTER);
	}

	@Override
	public boolean isGrabbable(Component c) {
		if (workingArea != null && workingArea.isAncestorOf(c))
			return false;
		return true;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public JComponent getWorkingArea() {
		return workingArea;
	}

//	public String getText() {
//		return workingArea.getText();
//	}

	public String getName() {
		return name;
	}

	public void setMaxWidth(int width) {
		this.maxWidth = width;
	}

//	@Override
//	public void setFocused(boolean focused) {
//		super.setFocused(focused);
//		workingArea.getCaret().setVisible(focused);
//	}

	@Override
	public void setSelected(boolean selected) {
		super.setSelected(selected);
		genericHeader.setSelected(selected);
	}

	@Override
	public void dispose() {
		genericHeader.dispose();
	}

	@Override
	public String toString() {
		return name;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((name == null) ? 0 : name.hashCode());
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
		CfgVertex other = (CfgVertex) obj;
		if (name == null) {
			if (other.name != null) {
				return false;
			}
		} else if (!name.equals(other.name)) {
			return false;
		}
		return true;
	}

}
