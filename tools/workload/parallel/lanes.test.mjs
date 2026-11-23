import assert from "node:assert/strict";
import { planLanes, shard } from "./lanes.mjs";

const lanes = planLanes("chrome:2,firefox:1", true);
assert.deepEqual(lanes.map((l) => l.id), ["chrome-1", "chrome-2", "firefox-1", "safari-1"]);
const s = shard(["a", "b", "c", "d", "e"], lanes);
assert.deepEqual(s.get("chrome-1"), ["a", "e"]);
assert.deepEqual(s.get("safari-1"), ["d"]);
const all = [...s.values()].flat().sort();
assert.deepEqual(all, ["a", "b", "c", "d", "e"]); // every site exactly once
console.log("lanes tests ok");
