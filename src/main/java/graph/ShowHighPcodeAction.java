package graph;

import java.util.function.Consumer;

import docking.action.*;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.actions.AbstractDecompilerAction;

public class ShowHighPcodeAction extends AbstractDecompilerAction {

//	private PluginTool tool;
	private Consumer<DecompilerActionContext> onPerform;

	public ShowHighPcodeAction(Consumer<DecompilerActionContext> callback) {
		super("Show High Pcode Graph");

		onPerform = callback;
		setPopupMenuData(new MenuData(new String[] { "Show High Pcode Graph" }));
		setEnabled(true);
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		return true;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		onPerform.accept(context);
	}

}
