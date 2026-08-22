import { readFile, stat, writeFile } from "node:fs/promises";

export const CLI_EXIT = Object.freeze({ success: 0, failure: 1, usage: 2 });
export const MAX_CLI_INPUT_BYTES = 1024 * 1024;

export interface CliIo {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

export interface CliFileSystem {
  readonly stat: (path: string) => Promise<{ readonly size: number }>;
  readonly readFile: (path: string) => Promise<string>;
  readonly writeFile: (
    path: string,
    content: string,
    options?: { readonly flag?: "w" | "wx" },
  ) => Promise<void>;
}

export const nodeFileSystem: CliFileSystem = Object.freeze({
  stat: async (path: string) => stat(path),
  readFile: async (path: string) => readFile(path, "utf8"),
  writeFile: async (path: string, content: string, options?: { readonly flag?: "w" | "wx" }) =>
    writeFile(path, content, {
      encoding: "utf8",
      ...(options?.flag === undefined ? {} : { flag: options.flag }),
    }),
});

export function isBoundedPath(value: string): boolean {
  return value.length > 0 && value.length <= 4_096 && !value.includes("\u0000");
}

export function isBoundedFileSize(size: number): boolean {
  return Number.isSafeInteger(size) && size >= 0 && size <= MAX_CLI_INPUT_BYTES;
}
