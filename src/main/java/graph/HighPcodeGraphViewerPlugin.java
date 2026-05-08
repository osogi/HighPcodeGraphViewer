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

import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;

/**
 * Plugin entry point for the High P-Code graph viewer.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.GRAPH,
	shortDescription = "High P-Code Graph Viewer",
	description = "Visualizes the High P-Code graph for the current function."
)
//@formatter:on
public class HighPcodeGraphViewerPlugin extends ProgramPlugin {
	private HighPcodeGraphViewerProvider provider;

	public HighPcodeGraphViewerPlugin(PluginTool tool) {
		super(tool);

		provider = new HighPcodeGraphViewerProvider(tool, this);
		createActions();
	}

	private void updateProvider(DecompilerActionContext ctx) {
		if (ctx == null || ctx.getHighFunction() == null) {
			return;
		}
		provider.updateFunction(ctx.getHighFunction(), currentProgram);
		provider.setVisible(true);
	}

	private void createActions() {
		tool.addAction(new ShowHighPcodeAction(ctx -> updateProvider(ctx)));
	}

	@Override
	protected void selectionChanged(ProgramSelection sel) {
		provider.selectionChanged(sel);
	}

	@Override
	protected void programDeactivated(Program program) {
		provider.clear();
	}

	@Override
	protected void dispose() {
		provider.dispose();
	}
}
