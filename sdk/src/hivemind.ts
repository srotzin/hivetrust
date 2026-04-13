import { BaseClient, BaseClientConfig } from './client';
import {
  BrowseGlobalHiveOpts,
  HiveResponse,
  MemoryNode,
  MemoryStats,
  PublishGlobalHiveOpts,
  QueryMemoryOpts,
  StoreMemoryOpts,
} from './types';

export class HiveMindClient extends BaseClient {
  constructor(config: BaseClientConfig) {
    super(config);
  }

  /** Store a memory node — POST /v1/memory/store */
  store(opts: StoreMemoryOpts): Promise<HiveResponse<MemoryNode>> {
    return this.post<MemoryNode>('/v1/memory/store', opts);
  }

  /** Semantic query over stored memories — POST /v1/memory/query */
  query(opts: QueryMemoryOpts): Promise<HiveResponse<MemoryNode[]>> {
    return this.post<MemoryNode[]>('/v1/memory/query', opts);
  }

  /** Memory usage statistics — GET /v1/memory/stats */
  stats(): Promise<HiveResponse<MemoryStats>> {
    return this.get<MemoryStats>('/v1/memory/stats');
  }

  /** Delete a memory node — DELETE /v1/memory/:nodeId */
  delete(nodeId: string): Promise<HiveResponse<void>> {
    return this.del<void>(`/v1/memory/${encodeURIComponent(nodeId)}`);
  }

  /** Publish knowledge to the Global Hive — POST /v1/global_hive/publish */
  publishToGlobalHive(opts: PublishGlobalHiveOpts): Promise<HiveResponse> {
    return this.post('/v1/global_hive/publish', opts);
  }

  /** Browse the Global Hive — GET /v1/global_hive/browse */
  browseGlobalHive(opts?: BrowseGlobalHiveOpts): Promise<HiveResponse> {
    const params = new URLSearchParams();
    if (opts?.topic) params.set('topic', opts.topic);
    if (opts?.tags) params.set('tags', opts.tags.join(','));
    if (opts?.limit !== undefined) params.set('limit', String(opts.limit));
    if (opts?.offset !== undefined) params.set('offset', String(opts.offset));
    const qs = params.toString();
    return this.get(`/v1/global_hive/browse${qs ? `?${qs}` : ''}`);
  }
}
