import "dotenv/config";
import express from "express";
import cors from "cors";
import { registerFunctionRoutes } from "./routes/functions.js";

const app = express();

app.use(
  cors({
    origin: "*",
    allowedHeaders: "authorization, x-client-info, apikey, content-type, x-paystack-signature",
  })
);
app.options("*", cors());

// Paystack webhook requires the raw body for signature verification
app.post(
  "/api/paystack-webhook",
  express.raw({ type: "*/*" }),
  (req, res, next) => {
    req.rawBody = req.body;
    next();
  }
);

app.use((req, res, next) => {
  if (req.path === "/api/paystack-webhook") {
    return next();
  }

  return express.json({ limit: "2mb" })(req, res, next);
});

registerFunctionRoutes(app);

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

const port = Number(process.env.PORT || 4000);
app.listen(port, () => {
  console.log(`Backend listening on port ${port}`);
});

// Extend Express Request type for rawBody
declare global {
  namespace Express {
    interface Request {
      rawBody?: Buffer;
    }
  }
}
