import {
  JupyterFrontEnd,
  JupyterFrontEndPlugin,
} from '@jupyterlab/application';

import { ICommandPalette, IFrame } from '@jupyterlab/apputils';

import { PageConfig } from '@jupyterlab/coreutils';

import { ILauncher } from '@jupyterlab/launcher';

import { requestAPI } from './handler';

/**
 * The command IDs used by the server extension plugin.
 */
namespace CommandIDs {
  export const get = 'server:get-file';
}

/**
 * Initialization data for the jupysec extension.
 */
const extension: JupyterFrontEndPlugin<void> = {
  id: 'jupysec',
  autoStart: true,
  optional: [ILauncher],
  requires: [ICommandPalette],
  activate: async (
    app: JupyterFrontEnd,
    palette: ICommandPalette,
    launcher: ILauncher | null
  ) => {
    console.log('JupyterLab extension jupysec is activated!');

    // GET request
    try {
      const data = await requestAPI<any>('scorecard_update');
      console.log(data);
    } catch (reason) {
      console.error(`Error on GET /jupysec/scorecard_update.\n${reason}`);
    }

    // POST request
    /**
    const dataToSend = { name: 'George' };
    try {
      const reply = await requestAPI<any>('hello', {
        body: JSON.stringify(dataToSend),
        method: 'POST',
      });
      console.log(reply);
    } catch (reason) {
      console.error(
        `Error on POST /jupysec/hello ${dataToSend}.\n${reason}`
      );
    }
     */

    const { commands, shell } = app;
    const command = CommandIDs.get;
    const category = 'Security';

    commands.addCommand(command, {
      label: 'Get Server Content in a IFrame Widget',
      caption: 'Get Server Content in a IFrame Widget',
      execute: () => {
        const widget = new IFrameWidget();
        widget.update();
        shell.add(widget, 'main');
      },
    });

    palette.addItem({ command, category: category });

    if (launcher) {
      // Add launcher
      launcher.add({
        command: command,
        category: category,
      });
    }
  },
};

export default extension;

class IFrameWidget extends IFrame {
  constructor() {
    super();
    const baseUrl = PageConfig.getBaseUrl();
    this.url = baseUrl + 'jupysec/public/score.html';
    this.id = 'jupysec';
    this.title.label = 'Report Card';
    this.title.closable = true;
    this.node.style.overflowY = 'auto';
  }

  async update() {
    try {
      const data = await requestAPI<any>('scorecard_update');
      console.log(data);
    } catch (reason) {
      console.error(`Error on GET /jupysec/scorecard_update.\n${reason}`);
    }
  }
}