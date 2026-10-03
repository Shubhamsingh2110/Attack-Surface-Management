import { MongoClient, type Db } from "mongodb";
import { getRuntimeEnv } from "@/server/config/env";

declare global {
  var __asmMongoClientPromise: Promise<MongoClient> | undefined;
}

export async function getDatabase(): Promise<Db> {
  const { MONGODB_URI, MONGODB_DB } = getRuntimeEnv();
  if (!global.__asmMongoClientPromise) {
    global.__asmMongoClientPromise = new MongoClient(MONGODB_URI, {
      appName: "asm-control",
      maxPoolSize: 10,
      minPoolSize: 0,
      serverSelectionTimeoutMS: 5_000,
    }).connect();
  }
  return (await global.__asmMongoClientPromise).db(MONGODB_DB);
}
