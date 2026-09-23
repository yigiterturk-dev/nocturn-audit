import { createClient } from "@supabase/supabase-js";

// HOLE — the service_role key in an in-app helper (not a script or worker
// where it would be by design): RLS is fully bypassed by this client, and if it
// drifts into client code all the data is exposed.
export const yonetimIstemcisi = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
);
