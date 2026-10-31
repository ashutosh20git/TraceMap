// Bull Board for the TrustGate `reports` BullMQ queue (jobs are produced by the
// FastAPI service and consumed by the Python WeasyPrint worker).
import express from "express";
import { Queue } from "bullmq";
import { createBullBoard } from "@bull-board/api";
import { BullMQAdapter } from "@bull-board/api/bullMQAdapter.js";
import { ExpressAdapter } from "@bull-board/express";

const url = new URL(process.env.REDIS_URL ?? "redis://localhost:6379");
const connection = { host: url.hostname, port: Number(url.port || 6379) };
const reports = new Queue("reports", { connection });

const serverAdapter = new ExpressAdapter();
serverAdapter.setBasePath("/admin/queues");
createBullBoard({
  queues: [new BullMQAdapter(reports, { description: "Incident PDF reports (Jinja2 + WeasyPrint)" })],
  serverAdapter,
  options: { uiConfig: { boardTitle: "TrustGate reports" } },
});

const app = express();
app.use("/admin/queues", serverAdapter.getRouter());
app.get("/healthz", (_req, res) => res.json({ ok: true }));
const port = Number(process.env.PORT ?? 3001);
app.listen(port, () => console.log(`Bull Board on http://localhost:${port}/admin/queues`));
