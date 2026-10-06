export const EXIT = {
  CLEAN: 0,
  FINDINGS: 1,
  USAGE: 2,
  OWNERSHIP: 3,
  INTERNAL: 4,
} as const;

export type ExitCode = (typeof EXIT)[keyof typeof EXIT];
