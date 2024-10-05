declare module "index" {
  /**
   * Executes a command with the given arguments and callback.
   * @param argv - An array of strings representing the command arguments.
   * @param callback - A callback function that takes a message string as an argument.
   * @throws Will throw an error if argv is not an array or if any element in argv is not a string.
   */
  export function exec(
    argv: string[],
    callback: (message: string) => void
  ): void;
}
