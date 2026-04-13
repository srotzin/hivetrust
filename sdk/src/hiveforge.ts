import { BaseClient, BaseClientConfig } from './client';
import {
  Census,
  CrossbreedOpts,
  EvolveOpts,
  Genome,
  HiveResponse,
  MintOpts,
  Pheromone,
} from './types';

export class HiveForgeClient extends BaseClient {
  constructor(config: BaseClientConfig) {
    super(config);
  }

  /** Mint a new agent genome (FREE) — POST /v1/forge/mint */
  mint(opts: MintOpts): Promise<HiveResponse<Genome>> {
    return this.post<Genome>('/v1/forge/mint', opts);
  }

  /** Crossbreed two parent genomes — POST /v1/forge/crossbreed */
  crossbreed(opts: CrossbreedOpts): Promise<HiveResponse<Genome>> {
    return this.post<Genome>('/v1/forge/crossbreed', opts);
  }

  /** Trigger mutation / evolution — POST /v1/forge/evolve */
  evolve(opts: EvolveOpts): Promise<HiveResponse<Genome>> {
    return this.post<Genome>('/v1/forge/evolve', opts);
  }

  /** Retrieve a genome by ID — GET /v1/forge/genome/:id */
  getGenome(id: string): Promise<HiveResponse<Genome>> {
    return this.get<Genome>(`/v1/forge/genome/${encodeURIComponent(id)}`);
  }

  /** Population census — GET /v1/population/census */
  census(): Promise<HiveResponse<Census>> {
    return this.get<Census>('/v1/population/census');
  }

  /** Scan pheromone signals — GET /v1/pheromones/scan */
  scanPheromones(): Promise<HiveResponse<Pheromone[]>> {
    return this.get<Pheromone[]>('/v1/pheromones/scan');
  }
}
