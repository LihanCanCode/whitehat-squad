import type { Agent } from "../../core/types.js";
import { runLive } from "./live.js";
import { runStatic } from "./static.js";

export const agent: Agent = {
  id: "web-hardener",
  name: "WebHardener",
  role: "Checks headers, CORS, cookies and exposed files",
  modes: ["static", "live"],
  async run(ctx) {
    return ctx.mode === "live" ? runLive(ctx) : runStatic(ctx);
  },
};
