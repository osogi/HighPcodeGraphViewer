package graph.dfg;

import java.util.Collection;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;

public class PcodeVertex extends DfgVertex {

	PcodeOp pcode;

	public PcodeVertex(String name, PcodeOp pcode) {
		super(name, VertexType.PCODE);
		this.pcode = pcode;
	}

	@Override
	public Collection<Address> getAssociatedAddresses() {
		return List.of(pcode.getSeqnum().getTarget());
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((pcode == null) ? 0 : pcode.hashCode());
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
		PcodeVertex other = (PcodeVertex) obj;
		if (pcode == null) {
			if (other.pcode != null) {
				return false;
			}
		}
		else if (!pcode.equals(other.pcode)) {
			return false;
		}
		return true;
	}
}
