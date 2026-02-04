package graph.dfg;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class VarnodeVertex extends DfgVertex {

	Varnode vn; 
	public VarnodeVertex(String name, Varnode varnode) {
		super(name, VertexType.VARNODE);
		vn = varnode;
	}

	@Override
	public Collection<Address> getAssociatedAddresses() {
		List <Address> res = new LinkedList<>();
		
		Iterator<PcodeOp> pcodes = vn.getDescendants();
		while (pcodes.hasNext()) {
			res.add(pcodes.next().getSeqnum().getTarget());
		}
		
		return res;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((vn == null) ? 0 : vn.hashCode());
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
		VarnodeVertex other = (VarnodeVertex) obj;
		if (vn == null) {
			if (other.vn != null) {
				return false;
			}
		}
		else if (!vn.equals(other.vn)) {
			return false;
		}
		return true;
	}
}
