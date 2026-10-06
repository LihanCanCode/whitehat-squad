/**
 * Shared source engine for the agents: lexer -> facts -> units -> taint -> guards.
 * See ./README.md for a worked example.
 */

// Lexing and offsets
export { createSource } from "./lexer.js";
export type { LexOptions, Source } from "./lexer.js";
export { lineOf, lineText, snippetAt } from "./lines.js";

// Structure helpers (operate on `Source.bare`)
export { exprEnd, matchClose, matchOpen, skipWs, splitArgs } from "./scan.js";
export type { Span } from "./scan.js";
export { parseBindingNames, parseParams, splitTopLevel } from "./bindings.js";
export type { ParamInfo } from "./bindings.js";

// File facts
export { classifyFile, classifyPath, fileDirectives, hasInlineUseServer, isGeneratedPath, isTestPath, isVendorPath, routeFromPath } from "./facts.js";
export type { ClassifyOptions, Directives, FileKind } from "./facts.js";

// Function units and route registrations
export { findUnits, handlerUnits, unitAt, unitBody } from "./units.js";
export type { FunctionUnit, UnitKind, UnitRole } from "./units.js";
export { findRouteRegistrations } from "./routes.js";
export type { RouteRegistration } from "./routes.js";

// Taint
export { analyzeTaint, DEFAULT_SANITIZERS, REQUEST_SOURCES } from "./taint.js";
export type { SourcePattern, TaintAnalysis, TaintSpec } from "./taint.js";

// Guards
export { AUTH_CHECK, GUARDS, guardMatches, OWNERSHIP, RATE_LIMIT, SIGNATURE_CHECK, unitHas, VALIDATION } from "./guards.js";
export type { GuardDef, GuardName, GuardOptions } from "./guards.js";
