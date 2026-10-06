/** Detects lifecycle-script commands that fetch, decode or evaluate code at install time. */

const REMOTE_URL = /https?:\/\//i;
const RUNNER = /\b(?:curl|wget|bash|powershell|pwsh|iex|invoke-webrequest|invoke-expression|eval)\b|node\s+(?:-e|--eval|-p)\b/i;
const PIPE_TO_SHELL = /\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:(?:ba|z|da)?sh|node)\b/i;
const BASE64_TO_SHELL = /\bbase64\s+(?:-d|-D|--decode)\b[^;&]*\|\s*(?:sudo\s+)?(?:(?:ba|z|da)?sh|node)\b/i;
const EVAL_OR_ATOB = /\beval\s*\(|\batob\s*\(/;
/** `npx pkg@latest`, `pnpm dlx pkg@latest`, `bunx pkg@latest`, `npm exec pkg@latest`: runs whatever was published last. */
const LATEST_RUNNER = /\b(?:npx|bunx|pnpm\s+dlx|yarn\s+dlx|npm\s+exec)\b[^;&|]*@latest\b/i;
const NODE_INLINE = /\bnode\s+(?:-e|--eval|-p|--print)\b([\s\S]*)/i;
/** What makes an inline `node -e` snippet more than a harmless one-liner. */
const NODE_INLINE_RISK = /child_process|\b(?:exec|execSync|spawn|spawnSync)\s*\(|require\s*\(\s*['"](?:https?|net|dgram|tls)['"]\s*\)|\bfetch\s*\(|\bnew\s+Function\b|Buffer\.from\([^)]*base64|process\.binding/i;

export function isRemoteExec(command: string): boolean {
  if (REMOTE_URL.test(command) && RUNNER.test(command)) return true;
  if (PIPE_TO_SHELL.test(command) || BASE64_TO_SHELL.test(command)) return true;
  if (EVAL_OR_ATOB.test(command) || LATEST_RUNNER.test(command)) return true;
  const inline = NODE_INLINE.exec(command)?.[1];
  return inline !== undefined && NODE_INLINE_RISK.test(inline);
}
