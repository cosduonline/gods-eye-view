import { defineConfig } from 'vite';
import { standaloneConfig } from '../server/standalone/vite.config.js';

// Serve the upstream production build with its original proxy middleware.
// Provider Settings is dev-only upstream; expose its original middleware behind
// the existing authenticated gateway as well so the controls remain available.
export default defineConfig(({ command, mode }) => {
  const config = standaloneConfig({ command, mode });
  config.plugins = config.plugins.map((plugin) => {
    if (plugin?.name !== 'gev-key-setup') return plugin;
    return { ...plugin, apply: (_config, env) => env.command === 'serve', configurePreviewServer: plugin.configureServer };
  });
  return config;
});
