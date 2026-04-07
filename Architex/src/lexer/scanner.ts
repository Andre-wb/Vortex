/** Phase 1: split source into annotated lines, strip blanks and comments. */

export interface Line {
  indent:  number;
  text:    string;
  lineNum: number;
}

export function scanLines(src: string): Line[] {
  return src
    .split('\n')
    .map((raw, i): Line => {
      const trimmed = raw.trimStart();
      return {
        indent:  raw.length - trimmed.length,
        text:    trimmed.trimEnd(),
        lineNum: i + 1,
      };
    })
    .filter(l => l.text.length > 0 && !l.text.startsWith('//'));
}
