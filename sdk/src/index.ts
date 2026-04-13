import { BaseClientConfig } from './client';
import { HiveAgentClient } from './hiveagent';
import { HiveForgeClient } from './hiveforge';
import { HiveLawClient } from './hivelaw';
import { HiveMindClient } from './hivemind';
import { HiveTrustClient } from './hivetrust';
import { HiveClientConfig } from './types';

export class HiveClient {
  readonly trust: HiveTrustClient;
  readonly mind: HiveMindClient;
  readonly forge: HiveForgeClient;
  readonly law: HiveLawClient;
  readonly agent: HiveAgentClient;

  constructor(config: HiveClientConfig) {
    const timeoutMs = config.timeoutMs ?? 10_000;

    const shared: Pick<BaseClientConfig, 'apiKey' | 'did' | 'internalKey' | 'timeoutMs'> = {
      apiKey: config.apiKey,
      did: config.did,
      internalKey: config.internalKey,
      timeoutMs,
    };

    this.trust = new HiveTrustClient({
      baseUrl: config.hiveTrustUrl ?? 'https://hivetrust.onrender.com',
      ...shared,
    });

    this.mind = new HiveMindClient({
      baseUrl: config.hiveMindUrl ?? 'https://hivemind-1-52cw.onrender.com',
      ...shared,
    });

    this.forge = new HiveForgeClient({
      baseUrl: config.hiveForgeUrl ?? 'https://hiveforge-lhu4.onrender.com',
      ...shared,
    });

    this.law = new HiveLawClient({
      baseUrl: config.hiveLawUrl ?? 'https://hivelaw.onrender.com',
      ...shared,
    });

    this.agent = new HiveAgentClient({
      baseUrl: config.hiveAgentUrl ?? 'https://hiveagent.onrender.com',
      ...shared,
    });
  }
}

// Re-export everything for convenience
export { HiveTrustClient } from './hivetrust';
export { HiveMindClient } from './hivemind';
export { HiveForgeClient } from './hiveforge';
export { HiveLawClient } from './hivelaw';
export { HiveAgentClient } from './hiveagent';
export { BaseClient } from './client';
export * from './types';
