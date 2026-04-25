// HiveOracle — spectral price mapping (ESM port).
//
// MUST stay regime-name identical to hivebank/src/lib/spectral.js.
// HiveTrust uses this only to validate that a regime string the issuer is
// asked to bake into a ticket is a known regime — the LIVE classification
// happens on hivebank.

export const REGIMES = [
  { name: 'STABLE_RED',     max: 0.005, line: 'Halpha', wavelength_nm: 656.3, hex: '#FF2A1F' },
  { name: 'NORMAL_CYAN',    max: 0.020, line: 'Hbeta',  wavelength_nm: 486.1, hex: '#1FE6FF' },
  { name: 'ELEVATED_BLUE',  max: 0.050, line: 'Hgamma', wavelength_nm: 434.0, hex: '#4A7BFF' },
  { name: 'HIGH_VIOLET',    max: 0.100, line: 'Hdelta', wavelength_nm: 410.2, hex: '#7A1FFF' },
  { name: 'EXTREME_UVA',    max: 0.250, line: 'Lyalpha', wavelength_nm: 121.6, hex: '#9D00FF' },
  { name: 'CRISIS_UVB',     max: Infinity, line: 'Lybeta', wavelength_nm: 102.6, hex: '#5D00FF' },
];

export const REGIME_NAMES = new Set([...REGIMES.map(r => r.name), 'WARMUP']);

export function isValidRegime(name) {
  return REGIME_NAMES.has(String(name).toUpperCase());
}
