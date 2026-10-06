/**
 * Damerau-Levenshtein distance (optimal string alignment variant): insertions, deletions,
 * substitutions and adjacent transpositions each cost 1.
 *
 * `cap` bounds the work: the result is exact when it is <= cap, otherwise exactly cap + 1.
 * It returns early when the length gap alone exceeds the cap, and again as soon as two
 * consecutive rows of the matrix have no cell within the cap (a transposition reaches back
 * two rows, so one row is not enough to prove the distance can never come back down).
 */
export function damerauLevenshtein(a: string, b: string, cap = Number.POSITIVE_INFINITY): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > cap) return cap + 1;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const cols = b.length + 1;
  let twoBack: number[] = [];
  let prev = Array.from({ length: cols }, (_, j) => j);
  let prevMin = 0;

  for (let i = 1; i <= a.length; i++) {
    const row = new Array<number>(cols).fill(0);
    row[0] = i;
    let rowMin = i;
    for (let j = 1; j < cols; j++) {
      const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
      let best = Math.min((prev[j] ?? 0) + 1, (row[j - 1] ?? 0) + 1, (prev[j - 1] ?? 0) + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        best = Math.min(best, (twoBack[j - 2] ?? 0) + 1);
      }
      row[j] = best;
      if (best < rowMin) rowMin = best;
    }
    if (rowMin > cap && prevMin > cap) return cap + 1;
    twoBack = prev;
    prev = row;
    prevMin = rowMin;
  }
  const distance = prev[b.length] ?? 0;
  return distance > cap ? cap + 1 : distance;
}
