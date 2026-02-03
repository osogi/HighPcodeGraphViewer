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

import java.awt.Rectangle;
import java.awt.Shape;
import java.awt.geom.Point2D;
import java.util.*;
import java.util.function.Function;

import ghidra.app.plugin.core.functiongraph.graph.layout.flowchart.OrthogonalEdgeRouter;
import ghidra.app.plugin.core.functiongraph.graph.layout.flowchart.OrthogonalGridToLayoutMapper;
import ghidra.graph.*;
import ghidra.graph.graphs.DefaultVisualGraph;
import ghidra.graph.jung.JungDirectedGraph;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.graph.viewer.layout.*;
import ghidra.graph.viewer.vertex.VisualGraphVertexShapeTransformer;
import ghidra.util.exception.CancelledException;


public abstract class AbstractReverseFlowChartLayout<V extends VisualVertex, E extends VisualEdge<V>>
		extends AbstractVisualGraphLayout<V, E> {
	protected Comparator<E> edgeComparator;
	protected boolean leftAligned;

	protected AbstractReverseFlowChartLayout(DefaultVisualGraph<V, E> graph,
			Comparator<E> edgeComparator, boolean leftAligned) {
		super(graph, "Reverse Flow Chart");
		this.edgeComparator = edgeComparator;
		this.leftAligned = leftAligned;
	}

	@Override
	protected GridLocationMap<V, E> performInitialGridLayout(VisualGraph<V, E> g)
			throws CancelledException {

		List<V> roots = getRoots(g);

		GDirectedGraph<V, E> forest = toForest(g, roots, edgeComparator);
		GridLocationMap<V, E> grid = new GridLocationMap<>();

		for (V root: roots) {
			GridLocationMap<V, E> newGrid = computeGridLocationMap(g, forest, root);
			grid.add(newGrid, grid.height() + 1, 0); 
		}
		
		OrthogonalEdgeRouter<V, E> router = new OrthogonalEdgeRouter<>(grid);
		router.setColumnExclusionFunction(e -> getExcludedCols(grid, forest, e));
		router.computeAndSetEdgeArticulations(g.getEdges());

		return grid;
	}

	
	private void helperToForest(VisualGraph<V, E> origGraph, GDirectedGraph<V, E> forest, V vert, Set<V> addedVerts, Comparator<E> ec) {
		addedVerts.add(vert);
		forest.addVertex(vert);
		
		Collection<E> edges = origGraph.getInEdges(vert);
		List<E> sortedEdges = new ArrayList<>(edges);
		sortedEdges.sort(edgeComparator);
		
		for(E e: sortedEdges) {
			V parent = e.getStart();
			
			if(addedVerts.contains(parent)) {
				continue;
			}
			forest.addEdge(e);
			helperToForest(origGraph, forest, parent, addedVerts, ec);
		}
		
	}
	
	private GDirectedGraph<V, E> toForest(VisualGraph<V, E> g, List<V> roots, Comparator<E> ec) {
		Set<V> addedVerts = new HashSet<>();
		GDirectedGraph<V, E> forest = new JungDirectedGraph<V, E>();
		
		for (V r: roots) {
			helperToForest(g, forest, r, addedVerts, ec);
		}
		
		return forest;
	}

	@Override
	protected LayoutPositions<V, E> positionInLayoutSpaceFromGrid(VisualGraph<V, E> g,
			GridLocationMap<V, E> grid) throws CancelledException {

		boolean isCondensed = isCondensedLayout();
		Function<V, Shape> transformer = new VisualGraphVertexShapeTransformer<>();

		OrthogonalGridToLayoutMapper<V, E> layoutMap =
			new OrthogonalGridToLayoutMapper<V, E>(grid, transformer, isCondensed);

		Map<V, Point2D> vertexMap = layoutMap.getVertexLocations();
		Map<E, List<Point2D>> edgeMap = layoutMap.getEdgeLocations(vertexMap);

		LayoutPositions<V, E> positions = LayoutPositions.createNewPositions(vertexMap, edgeMap);

		// DEGUG triggers grid lines to be printed; useful for debugging
//		VisualGraphRenderer.setGridPainter(new GridPainter(layoutMap.getGridCoordinates()));

		layoutMap.dispose();
		return positions;
	}

	protected abstract List<V> getRoots(VisualGraph<V, E> g);

	@Override
	public boolean usesEdgeArticulations() {
		return true;
	}

	@Override
	protected Point2D getVertexLocation(V v, Column<V> col, Row<V> row,
			Rectangle bounds) {
		return getCenteredVertexLocation(v, col, row, bounds);
	}

	/**
	 * Creates a GridLocationMap for the subtree rooted at the given vertex. It does this by
	 * recursively getting grid maps for each of its children and then merging them together
	 * side by side.
	 * @param g the original graph
	 * @param tree the graph after edge removal to convert it into a tree
	 * @param v the root of the subtree to get a grid map for
	 * @return a GridLocationMap with the given vertex and all of its children position in the 
	 * grid.
	 */
	private GridLocationMap<V, E> computeGridLocationMap(GDirectedGraph<V, E> g,
			GDirectedGraph<V, E> tree, V v) {

		Collection<E> edges = tree.getInEdges(v);

		if (edges.isEmpty()) {
			GridLocationMap<V, E> grid = new GridLocationMap<>(v, 1, 1);
			return grid;
		}

		// get all child grids and merge them side by side

		List<E> sortedEdges = new ArrayList<>(edges);
		sortedEdges.sort(edgeComparator);
		E edge = sortedEdges.get(0);
		V parent = edge.getStart();
		int totalEdges = sortedEdges.size();

		GridLocationMap<V, E> parentGrid = computeGridLocationMap(g, tree, parent);
		int leftParentRootCol = parentGrid.getRootColumn();
		int rightParentRootCol = leftParentRootCol;
		for (int i = 1; i < totalEdges; i++) {
			edge = sortedEdges.get(i);
			parent = edge.getStart();
			GridLocationMap<V, E> nextGrid = computeGridLocationMap(g, tree, parent);
			int shift = merge(parentGrid, nextGrid, i, totalEdges);
			rightParentRootCol = nextGrid.getRootColumn() + shift;
		}
		int rootCol = (leftParentRootCol + rightParentRootCol) / 2;
		if (leftAligned) {
			rootCol = 1;
		}
		GridLocationMap<V, E> grid = new GridLocationMap<>(v, parentGrid.height() + 2, rootCol);
		grid.add(parentGrid, 0, 0);  // move child grid up 2: 1 for new root, 1 for edge row

		return grid;
	}

	private int merge(GridLocationMap<V, E> leftGrid, GridLocationMap<V, E> rightGrid, int i,
			int totalEdges) {

		GridRange[] ranges = leftGrid.getVertexColumnRanges();
		GridRange[] otherRanges = rightGrid.getVertexColumnRanges();

		int shift = computeShift(ranges, otherRanges);

		leftGrid.add(rightGrid, 0, shift);
		return shift;

	}

	private int computeShift(GridRange[] ranges, GridRange[] otherRanges) {
		int shift = 0;
		int commonHeight = Math.min(ranges.length, otherRanges.length);
		for (int i = 0; i < commonHeight; i++) {
			GridRange range = ranges[i];
			GridRange otherRange = otherRanges[i];
			int myMax = range.max;
			int otherMin = otherRange.min;
			if (myMax >= otherMin - 1) {
				int diff = myMax - otherMin + 2; // we want 1 empty column between
				shift = Math.max(shift, diff);
			}
		}
		return shift;
	}

	@SuppressWarnings("unchecked")
	@Override
	public VisualGraph<V, E> getVisualGraph() {
		return (VisualGraph<V, E>) getGraph();
	}

	/**
	 * Returns a range of columns that we don't want to attempt to perform column routing through.
	 * Specifically, this is for back edges where we don't want them to route through columns that
	 * cut through any of its parents sub trees. This will force the routing algorithm to route
	 * around a nodes containing sub-tree instead of through it.
	 * @param grid the grid map that will be examined to find a routing column that doesn't
	 * have any blocking vertices.
	 * @param tree the tree version of the original graph
	 * @param e the edge to examine to find its parent's subtree column bounds
	 * @return a minimum and maximum column index through which the back edge should not be routed
	 */
	private GridRange getExcludedCols(GridLocationMap<V, E> grid, GDirectedGraph<V, E> tree, E e) {
		GridRange range = new GridRange();
		V v = e.getStart();
		V ancestor = e.getEnd();
		boolean isBackEdge = grid.row(v) >= grid.row(ancestor);
		if (!isBackEdge) {
			// no exclusions
			return new GridRange();
		}

		V parent = getParent(tree, v);
		while (parent != null) {
			Collection<V> children = tree.getSuccessors(parent);
			for (V child : children) {
				range.add(grid.col(child));
			}
			parent = getParent(tree, parent);
			if (parent == ancestor) {
				break;
			}
		}
		return range;
	}

	private V getParent(GDirectedGraph<V, E> tree, V v) {
		Collection<V> predecessors = tree.getPredecessors(v);
		if (predecessors == null || predecessors.isEmpty()) {
			return null;
		}
		return predecessors.iterator().next();
	}
}
