/**
 * HiveTrust — Agent Service Adapter
 * Re-exports from agent-identity.js with normalized signatures
 * for consumption by routes/api.js and mcp-server.js.
 */

export {
  registerAgent,
  getAgent,
  updateAgent,
  deactivateAgent,
} from './agent-identity.js';
