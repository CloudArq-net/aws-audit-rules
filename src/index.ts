/**
 * Public surface. Everything here is a pure function — nothing in this package
 * opens a socket, reads a file, or touches the DOM.
 */
export type {
  AnalysisResult, Evidence, Finding, Fix, Gap, Note, Severity, SourceKind,
} from './types';
export { ParseError } from './types';
export { safeParseJson, unwrapList } from './parse/json';
export {
  analyzeSecurityGroups, describePortRange, isAllPortsRule, isIpv6OnlyExposure,
  isOpenToWorld, normalizeProtocol, ruleCoversPort, SG_RULE_IDS,
} from './rules/securityGroups';
export type {
  IpPermission, IpRange, Ipv6Range, PrefixListId, SecurityGroup, SgAnalysis,
  UserIdGroupPair,
} from './rules/securityGroups';
export {
  analyzeAddresses, analyzeSnapshots, analyzeVolumes, COST_RULE_IDS,
  gp2BaselineIops, isBackupArtefact, monthlyForEbs, parseAwsTimestamp,
  PRICING_BASIS,
} from './rules/cost';
export type { Address, Snapshot, Tag, Volume } from './rules/cost';
export { analyzeBedrock, BEDROCK_RULE_IDS } from './rules/bedrock';
export type {
  BedrockInput, CloudWatchConfig, Guardrail, LoggingConfig, LoggingResponse,
  S3Config,
} from './rules/bedrock';

/** Made-up sample data, for demos. Covers shapes a real account often lacks. */
export { EXAMPLE_PASTE, EXAMPLE_LABEL } from './fixtures/example';

/** The usual entry point — hand it a paste and it works out what's in it. */
export { analyzeAll, describeMissing, INPUT_KINDS } from './analyze';
export type {
  FullResult, InputKind, MissingInput, RecognizedInput, UnrecognizedInput,
} from './analyze';
