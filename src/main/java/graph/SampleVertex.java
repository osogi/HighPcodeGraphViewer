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
import java.util.Set;



import javax.swing.JTextArea;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;

import ghidra.graph.viewer.vertex.DockingVisualVertex;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOpAST;
import graph.dfg.CfgVertex;
import graph.dfg.DfgVertex;
import ghidra.program.model.pcode.PcodeOp;


/**
 * A vertex for the {@link SampleGraphPlugin}
 */
public class SampleVertex extends CfgVertex {
	
//	public boolean isEntry = false;
	public PcodeBlockBasic hBasicBlock;

	private Map<Address, Set<Integer>> addressLineNumberMap = new HashMap<>();
	
	DefaultHighlighter.DefaultHighlightPainter myPainter;
	
	private void setupTextArea(JTextArea textArea) {
		textArea.setEditable(false);
		
		String preview = "";
		addressLineNumberMap.clear();
		
		Iterator<PcodeOp> pcodes = hBasicBlock.getIterator();
		int lineNumberCount = 0;
		int maxLineSize = 0;
		
		while (pcodes.hasNext())
		{
			PcodeOp currentOp = pcodes.next();
			Address opAddress = currentOp.getSeqnum().getTarget();
			
			Set<Integer> val = addressLineNumberMap.getOrDefault(opAddress, new HashSet<>());
			val.add(lineNumberCount);
			addressLineNumberMap.putIfAbsent(opAddress, val);
			lineNumberCount++;
			
			String line = opAddress + ": " + currentOp.toString();
			
			if (line.length() > maxLineSize) 
				maxLineSize = line.length();
			preview += line + "\n";
			
		}

		setMaxWidth(10000);
		textArea.setText(preview);		
//		textArea.setSize(1000, 1000);
		textArea.setColumns(maxLineSize + 10); 
		textArea.setRows(lineNumberCount);
		
	}
	
	public SampleVertex(String name, PcodeBlockBasic hbb) {
		super(name, hbb);
		hBasicBlock = hbb;
		myPainter = new DefaultHighlighter.DefaultHighlightPainter(java.awt.Color.YELLOW);
		
//		setupTextArea(getTextArea());
	}

	private void highlighString(JTextArea textArea, int target) {
		DefaultHighlighter highlighter = (DefaultHighlighter) textArea.getHighlighter();

		try {
			int startOffset = textArea.getLineStartOffset(target);
			int endOffset = textArea.getLineStartOffset(target+1);
			
			highlighter.addHighlight(startOffset, endOffset, myPainter);

		} catch (BadLocationException e) {
			e.printStackTrace();
		}
	}
		
	public void selectByAddress(Address currentAddress) {
//		JTextArea textArea = getTextArea();
//
//		DefaultHighlighter highlighter = (DefaultHighlighter) textArea.getHighlighter();
//		highlighter.setDrawsLayeredHighlights(false);
//		
//		highlighter.removeAllHighlights();
//		
//		Set<Integer> s = addressLineNumberMap.get(currentAddress);
//		if (s == null)
//			return;
//		
//		for (int i : s) {
//			highlighString(textArea, i);
//		}
	}
	
	@Override
	public void setSelected(boolean val) {
		super.setSelected(val);
		
		if (val == false) {
			selectClean();
		}
	}
	
	public void selectClean() {
//		JTextArea textArea = getTextArea();
//		DefaultHighlighter highlighter = (DefaultHighlighter) textArea.getHighlighter();
//		highlighter.removeAllHighlights();
	}

}
